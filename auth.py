import datetime
import bcrypt
import enum
from getpass import getpass
from typing import Tuple, Optional
from db import User


class AuthResult(enum.Enum):
    SUCCESS = (0, 'Авторизация успешна')
    FAILURE = (1, 'Ошибка авторизации!')
    NO_SUCH_USER = (2, 'Пользователя с таким логином не существует!')
    USER_ALREADY_EXISTS = (3, 'Пользователь с таким логином уже зарегистрирован!')



def register_user() -> Tuple[AuthResult, User]:
    name = input('Введите ваше имя: ')
    login = input('Введите логин, который будет использоваться для авторизации: ')

    passwords_match = False
    while not passwords_match:
        password = getpass('Введите ваш пароль: ')
        repeat_password = getpass('Подтвердите ваш пароль:')

        if password == repeat_password:
            passwords_match = True

    user = User.get_or_none(User.login == login)

    if user is not None:
        return AuthResult.USER_ALREADY_EXISTS, None

    user = User()
    user.name = name
    user.login = login
    user.password_hash = bcrypt.hashpw(password.encode(), salt=bcrypt.gensalt())
    user.last_login = datetime.datetime.now()

    user.save()

    return AuthResult.SUCCESS, user


def login_user() -> Tuple[AuthResult, User]:
    login = input('Введите логин: ')
    password = getpass('Введите пароль: ')

    user = User.get_or_none(User.login == login)

    if user is None:
        return AuthResult.NO_SUCH_USER, None

    # password has to be in bytes, not string
    if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return AuthResult.FAILURE, None

    user.last_login = datetime.datetime.now()
    user.save()

    return AuthResult.SUCCESS, user
