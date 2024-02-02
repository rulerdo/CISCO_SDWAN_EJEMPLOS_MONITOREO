import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
from time import time


class sdwan_manager:
    def __init__(self, server, port, username, password):

        self.username = username
        self.password = password
        self.server = server
        self.port = port
        self.host = server + ":" + port
        self.cookie = self.get_auth_cookie()
        self.token = self.get_auth_token()

    def get_auth_cookie(self):

        url = f"https://{self.host}/j_security_check"

        payload = f"j_username={self.username}&j_password={self.password}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.request(
            "POST", url, headers=headers, data=payload, verify=False
        )

        cookie = response.cookies.get_dict()["JSESSIONID"]

        return cookie

    def get_auth_token(self):

        url = f"https://{self.server}/dataservice/client/token"

        payload = {}
        headers = {"Cookie": f"JSESSIONID={self.cookie}"}

        response = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )

        token = response.text
        if token:
            print(f"Conectado a vManage! {self.host}\n")

        return token

    def send_request(self, action, resource, body):

        print("Obteniendo recurso:", resource)
        url = f"https://{self.host}/dataservice{resource}"

        headers = {
            "X-XSRF-TOKEN": self.token,
            "Cookie": f"JSESSIONID={self.cookie}",
            "Content-Type": "application/json",
        }

        response = requests.request(
            action, url, headers=headers, data=body, verify=False
        )

        return response

    def logout(self):

        url = f"https://{self.host}/logout?nocache={str(int(time()))}"

        payload = {}

        headers = {
            "Cookie": f"JSESSIONID={self.cookie}",
        }

        response = requests.request(
            "GET", url, headers=headers, data=payload, verify=False
        )

        message = (
            "Sesion a vManage cerrada!"
            if response.status_code == 200
            else "Problemas cerrando sesion"
        )
        print(message)
