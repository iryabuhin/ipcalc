import sys
from colorama import Fore, Back, Style
from tasks import *
from db import create_tables
from auth import login_user, register_user, AuthResult
from typing import List, Union, Optional, Tuple


def get_option_number(options: List[str], prompt: Optional[str] = None) -> int:
    if prompt is None:
        prompt = "Выберите опцию: "

    while True:
        try:
            for index, option in enumerate(options):
                print("{}) {}".format(str(index + 1), option))
            result = int(input(prompt))
        except ValueError:
            print("Некорректный ввод! Попробуйте снова")
        else:
            if result > len(options):
                print("Неправильный номер опции! Попробуйте снова!")
            else:
                return result


class Application:

    tasks = [
        GetClassfulNetworkInfo,
        TwoAddressesInOneSubnet,
        CheckSubnetMaskCorrectness,
        MaxMaskLenForTwoAddresses,
        SubnetAddrAndBroadcastAddrTask,
        AddrIsSubnetAddrForGivenAddrTask,
    ]

    def __init__(self):
        self.tasks.sort(key=lambda t: t._id)
        self._tasks_by_id = {t._id: t for t in self.tasks}

    def propmt_for_login(self):
        option = get_option_number(["Регистрация", "Авторизация"])

        result = None

        if option == 1:
            return register_user()

        return login_user()

    def get_task_id_from_user(self):
        while True:
            try:
                task_id = int(input("Выберите режим работы программы: "))
            except ValueError:
                print("Некорректный ввод! Попробуйте снова!")
            else:
                try:
                    self._tasks_by_id[task_id]
                except KeyError:
                    print("Задачи с таким идентификатором не существует!")
                else:
                    return task_id

    def run(self) -> None:
        auth_result, user = self.propmt_for_login()

        if auth_result in (
            AuthResult.NO_SUCH_USER,
            AuthResult.FAILURE,
            AuthResult.USER_ALREADY_EXISTS,
        ):
            print(Back.BLACK, Fore.RED, Style.BRIGHT, auth_result.value[1])
            print(Style.RESET_ALL)
            return

        print(f"Добрый день, {Fore.GREEN + Style.BRIGHT}{user.name}!")
        print(Style.RESET_ALL)

        for _id, _task in self._tasks_by_id.items():
            print("{}) {}".format(str(_id), str(_task.description)))

        while True:
            task_id = self.get_task_id_from_user()

            task = self._tasks_by_id[task_id]()
            task.perform_task()


def main(argv):
    app = Application()
    create_tables()
    try:
        app.run()
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    sys.exit(main(sys.argv))
