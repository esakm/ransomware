from abc import ABC, abstractmethod


class Algo(ABC):
    '''
       Configure the algo with everything it needs (basically just keys)
       :return None
    '''

    @abstractmethod
    def configure_algo(self, **kwargs):
        pass

    @abstractmethod
    def encrypt(self, input_file):
        pass

    @abstractmethod
    def decrypt(self, input_file):
        pass
