from social.strategies.django_strategy import DjangoStrategy


class DRFStrategy(DjangoStrategy):
    def __init__(self, storage, request=None, tpl=None):
        self.request = request
        self.session = {}
        self.data = {}

        if request:
            try:
                self.session = request.session
            except AttributeError:
                # in case of token auth session can be disabled at all
                pass
            self.data.update(request.data)

        super(DjangoStrategy, self).__init__(storage, tpl)

    def request_data(self, merge=True):
        return self.data


class StatelessDRFStrategy(DRFStrategy):
    SESSION_KEY_NAME = 'session_data'

    def __init__(self, storage, request=None, tpl=None):
        self.request = request
        self.session = {}
        self.data = {}

        if request:
            self.data.update(request.data)
            try:
                self.session = self.extract_session_from_payload(self.data)
            except KeyError:
                pass

        super(DjangoStrategy, self).__init__(storage, tpl)

    def extract_session_from_payload(self, payload):
        return payload.pop(self.SESSION_KEY_NAME)

    def finalize_response(self, response):
        self.reinsert_session_into_payload(response.data, self.session)

    def reinsert_session_into_payload(self, payload, session):
        payload[self.SESSION_KEY_NAME] = session
