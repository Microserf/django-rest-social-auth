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
