import pytest
import pprint

from ctypes import CDLL, POINTER, Structure, CFUNCTYPE, cast, byref, sizeof
from ctypes import c_void_p, c_size_t, c_char_p, c_char, c_int

from src.pam import PamHandle, PamMessage, PamResponse, PamConv
from src.pam import PamAuthenticator


@pytest.fixture(scope="module")
def pam_fixture(request, config_fixture):
    pam_obj = PamAuthenticator()
    yield pam_obj


# these initial tests don't really do much, they're here for enlightenment
def test_PamHandle__subclass():
    assert issubclass(PamHandle, Structure)


def test_PamMessage__subclass():
    assert issubclass(PamMessage, Structure)


def test_PamResponse__subclass():
    assert issubclass(PamResponse, Structure)


def test_PamConv__subclass():
    assert issubclass(PamConv, Structure)


def test_PamHandle__value():
    x = PamHandle()
    assert x.handle == c_void_p(0).value


def test_PamMessage_hasattrs():
    x = PamMessage()
    assert hasattr(x, 'msg_style')
    assert hasattr(x, 'msg')


def test_PamResponse():
    x = PamResponse()
    assert hasattr(x, 'resp_retcode')
    assert hasattr(x, 'resp')

def test_PamAuthenticator():
    x = PamAuthenticator()
    assert hasattr(x, 'authenticate')
    assert hasattr(x, 'end')
    assert hasattr(x, 'open_session')
    assert hasattr(x, 'close_session')
    assert hasattr(x, 'misc_setenv')
    assert hasattr(x, 'putenv')
    assert hasattr(x, 'getenv')
    assert hasattr(x, 'getenvlist')

def test_null_service():
    x = PamAuthenticator()
    retval = x.authenticate("", "", service="\0")
    assert retval == False
    assert x.code == 4 # PAM_SYSTEM_ERR
    assert x.reason == 'strings may not contain NUL'
    assert x.handle == None

def test_bad_service():
    x = PamAuthenticator()
    retval = x.authenticate("asdf", "", service="asdf")
    assert retval == False
    assert x.reason == 'Authentication failure'
    assert x.code == 7 # PAM_AUTH_FAIL
    assert x.handle == None

def test_bad_auth():
    x = PamAuthenticator()
    retval = x.authenticate("asdf", "")
    assert retval == False
    assert x.reason == 'User not known to the underlying authentication module'
    assert x.code == 10 # PAM_USER_UNKNOWN
    assert x.handle == None
