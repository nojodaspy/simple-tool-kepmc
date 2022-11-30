import os
import time
import sys
from colorama import Fore
import socket
from mcstatus import JavaServer
import threading
from queue import *
import hashlib
import requests
import re
import json as jsond 
import binascii 
from uuid import uuid4  
import platform 
import nmap
import subprocess
import win32security  
import requests  
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from pypresence import Presence
import json
import uuid
import datetime
import asyncio, psutil
from pwinput import pwinput
from websockets import connect
import shutil
#from socket import *

##AuthMe System
try:  
    s = requests.Session() 
    s.get('https://google.com')
except requests.exceptions.RequestException as e:
    print(e)
    time.sleep(3)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):

        if self.sessionid != "":
            print("Se encuentra iniciado!")
            time.sleep(2)
            os._exit(1)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("La aplicacion no existe, Contacta con el desarollador")
            os._exit(1)

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("Nueva version disponible.")
                download_link = json["download"]
                os.system(f"start {download_link}")
                os._exit(1)
            else:
                print("Contacta con el owner")
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])
    
    def checkinit(self):
        if not self.initialized:
            print("Iniciando.")
            time.sleep(2)
            os._exit(1)


    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("register").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print(f"{Fore.GREEN}[ $ ] Usuario Registrado correctamente")
            el = Minecraft()
            el.minecraft()
            self.__load_user_data(json["info"])
        else:
            print(f"{Fore.RED}[ $ ] No encontramos tu licencia en nuestra base de datos. Porfavor contacta con el Owner.")
            exit()
            #print(json["message"])
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("login").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print(f"{Fore.GREEN} [ $ ] Usuario logueado correctamente")
            el = Minecraft()
            el.minecraft()
            el.menu()
        else:
            print(f"{Fore.RED} [ $ ] Tu usuario no esta registrado.")
            time.sleep(2)
            el = Minecraft()
            el.authme()
            #print(json["message"])
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("license").encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print(f"{Fore.GREEN} [ $ ] Usuario Registrado correctamente")
            time.sleep(2)
            self.menu()
        else:
            print("Ocurrio un error.")
            #print(json["message"])
            os._exit(1)

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("var").encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("getvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("setvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("check").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def __do_request(self, post_data):
        try:
            rq_out = s.post(
                "https://keyauth.win/api/1.0/", data=post_data, timeout=30
            )
            return rq_out.text
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[ $ ] Tiempo Agotado - Revisa tu conexion.")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid



class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Contacta con el owner, esto es un error")
            os._exit(1)

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Contacta con el owner, esto es un error.")
            os._exit(1)



class Minecraft():
    

    def getchecksum(self):
        md5_hash = hashlib.md5()
        file = open(''.join(sys.argv), "rb")
        md5_hash.update(file.read())
        digest = md5_hash.hexdigest()
        return digest

    ##AUTHME - MENU
    def register(self):
        keyauthapp = api(
        name = "kepcraft",
        ownerid = "qill8Pc8aW",
        secret = "a822b8640a94537776edb0f5306a815fc36242f48f5acfd4700025b8e4ec7804",
        version = "1.0",
        hash_to_check = self.getchecksum()
        )

        os.system('cls')
        os.system('title AuthMe KepCraft V1.0  - NoJodas#6364')
        banner = f"""{Fore.LIGHTBLUE_EX}
        :::    ::: :::::::::: :::::::::     :::     :::    ::: ::::::::::: :::    ::: ::::    ::::  :::::::::: 
        :+:   :+:  :+:        :+:    :+:  :+: :+:   :+:    :+:     :+:     :+:    :+: +:+:+: :+:+:+ :+:        
        +:+  +:+   +:+        +:+    +:+ +:+   +:+  +:+    +:+     +:+     +:+    +:+ +:+ +:+:+ +:+ +:+        
        +#++:++    +#++:++#   +#++:++#+ +#++:++#++: +#+    +:+     +#+     +#++:++#++ +#+  +:+  +#+ +#++:++#   
        +#+  +#+   +#+        +#+       +#+     +#+ +#+    +#+     +#+     +#+    +#+ +#+       +#+ +#+        
        #+#   #+#  #+#        #+#       #+#     #+# #+#    #+#     #+#     #+#    #+# #+#       #+# #+#        
        ###    ### ########## ###       ###     ###  ########      ###     ###    ### ###       ### ########## 
        
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                             ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        usuario = input(f"{Fore.WHITE} [ $ ] Usuario >> ").replace("None", "")
        password = input(f"{Fore.WHITE} [ $ ] Contraseña >> ").replace("None", "")
        license = input(f"{Fore.WHITE} [ $ ] Licencia >> ").replace("None", "")
        keyauthapp.register(usuario, password, license)

    def logueo(self):
        keyauthapp = api(
        name = "kepcraft",
        ownerid = "qill8Pc8aW",
        secret = "a822b8640a94537776edb0f5306a815fc36242f48f5acfd4700025b8e4ec7804",
        version = "1.0",
        hash_to_check = self.getchecksum()
        )
        os.system('cls')
        os.system('title AuthMe - KepCraft V1.0  - NoJodas#6364')
        banner = f"""{Fore.LIGHTBLUE_EX}
        :::    ::: :::::::::: :::::::::     :::     :::    ::: ::::::::::: :::    ::: ::::    ::::  :::::::::: 
        :+:   :+:  :+:        :+:    :+:  :+: :+:   :+:    :+:     :+:     :+:    :+: +:+:+: :+:+:+ :+:        
        +:+  +:+   +:+        +:+    +:+ +:+   +:+  +:+    +:+     +:+     +:+    +:+ +:+ +:+:+ +:+ +:+        
        +#++:++    +#++:++#   +#++:++#+ +#++:++#++: +#+    +:+     +#+     +#++:++#++ +#+  +:+  +#+ +#++:++#   
        +#+  +#+   +#+        +#+       +#+     +#+ +#+    +#+     +#+     +#+    +#+ +#+       +#+ +#+        
        #+#   #+#  #+#        #+#       #+#     #+# #+#    #+#     #+#     #+#    #+# #+#       #+# #+#        
        ###    ### ########## ###       ###     ###  ########      ###     ###    ### ###       ### ########## 
        
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                             ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        usuario = input(f"{Fore.WHITE} [ $ ] Usuario >> ").replace("None", "")
        password = input(f"{Fore.WHITE} [ $ ] Contraseña >> ").replace("None", "")
        keyauthapp.login(usuario, password)

    def authme(self):
        os.system('cls')
        os.system('title AuthMe - KepCraft V1.0  - NoJodas#6364')
        banner = f"""{Fore.LIGHTBLUE_EX}
        :::    ::: :::::::::: :::::::::     :::     :::    ::: ::::::::::: :::    ::: ::::    ::::  :::::::::: 
        :+:   :+:  :+:        :+:    :+:  :+: :+:   :+:    :+:     :+:     :+:    :+: +:+:+: :+:+:+ :+:        
        +:+  +:+   +:+        +:+    +:+ +:+   +:+  +:+    +:+     +:+     +:+    +:+ +:+ +:+:+ +:+ +:+        
        +#++:++    +#++:++#   +#++:++#+ +#++:++#++: +#+    +:+     +#+     +#++:++#++ +#+  +:+  +#+ +#++:++#   
        +#+  +#+   +#+        +#+       +#+     +#+ +#+    +#+     +#+     +#+    +#+ +#+       +#+ +#+        
        #+#   #+#  #+#        #+#       #+#     #+# #+#    #+#     #+#     #+#    #+# #+#       #+# #+#        
        ###    ### ########## ###       ###     ###  ########      ###     ###    ### ###       ### ########## 
        
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                             ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        print(f"{Fore.YELLOW}                                          ☞ O P C I O N E S ☜")
        print("\n")
        print(f"{Fore.YELLOW}                                          ☞ [1] Login")
        print(f"{Fore.YELLOW}                                          ☞ [2] Register")
        print(f"{Fore.YELLOW}                                          ☞ [3] Exit")
        print("\n")
        message = input(f"{Fore.WHITE} [ $ ] Seleccione su opcion >> ").replace("None", "")

        if message == "1":
            self.logueo()
        
        if message == "2":
            self.register()
        
        if message == "3":
            exit()

    def range(self):
        os.system('cls')
        os.system('title Colocar el rango - KepCraft V1.0')
        banner = f"""{Fore.LIGHTBLUE_EX}
        :::    ::: :::::::::: :::::::::  :::::::::      :::     ::::    :::  ::::::::  :::::::::: 
        :+:   :+:  :+:        :+:    :+: :+:    :+:   :+: :+:   :+:+:   :+: :+:    :+: :+:        
        +:+  +:+   +:+        +:+    +:+ +:+    +:+  +:+   +:+  :+:+:+  +:+ +:+        +:+        
        +#++:++    +#++:++#   +#++:++#+  +#++:++#:  +#++:++#++: +#+ +:+ +#+ :#:        +#++:++#   
        +#+  +#+   +#+        +#+        +#+    +#+ +#+     +#+ +#+  +#+#+# +#+   +#+# +#+        
        #+#   #+#  #+#        #+#        #+#    #+# #+#     #+# #+#   #+#+# #+#    #+# #+#        
        ###    ### ########## ###        ###    ### ###     ### ###    ####  ########  ########## 

        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                         ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        print("\n")
        rango = input(f"{Fore.WHITE} [ $ ] Coloca el rango (Ejemplo: 127.0.0.*) >> ").replace("None", "")
		
        #puerto = input(f"{Fore.WHITE} [ $ ] Coloca un rango de puertos (Ejemplo: 25565-25590) >> ").replace("None", "")
        print(f"{Fore.WHITE} [ $ ] Empezando a escanear el rango, se escaneara con puertos default (1-65535), esto puede demorar algunos minutos...")
        os.system('nmap -p 1-65535 -T5 -Pn -A -v --open --exclude-ports 21,22,53,80,81,111,3306,2022,8096 ' + rango)
        print()
        print()
        input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
        self.minecraft()

    #def getinfo(self, ip, port):
     #   server = JavaServer.lookup(ip, port)
      # status = server.status()
       #print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Direccion de IP: {Fore.YELLOW}"+ ip +":"+port)
        #print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Puerto: {Fore.YELLOW}"+ port)
        #print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Jugadores Activos: {Fore.YELLOW}{str(status.players.online), str(status.players.max)}")
        #print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Version: {Fore.YELLOW}{status.version.name, str(status.version.protocol)}")
        #print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Descripcion: {Fore.YELLOW}" + re.sub(r'\ +', ' ', re.sub(r'(&|§)[a-z0-9]{1}|\n||\\n', '', ''.join([x.split('\'')[0] for x in str(status.description).split('\'text\': \'')])).replace('{', '')))
        #print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Mods: {Fore.YELLOW}[MODS]")
       

    def scan(self):
        os.system('cls')
        os.system('title Seleccionar Opcion - KepCraft V1.0')
        banner = f"""{Fore.LIGHTBLUE_EX}
        :::    ::: :::::::::: :::::::::  :::::::::   ::::::::  ::::::::: ::::::::::: 
        :+:   :+:  :+:        :+:    :+: :+:    :+: :+:    :+: :+:    :+:    :+:     
        +:+  +:+   +:+        +:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+    +:+     
        +#++:++    +#++:++#   +#++:++#+  +#++:++#+  +#+    +:+ +#++:++#:     +#+     
        +#+  +#+   +#+        +#+        +#+        +#+    +#+ +#+    +#+    +#+     
        #+#   #+#  #+#        #+#        #+#        #+#    #+# #+#    #+#    #+#     
        ###    ### ########## ###        ###         ########  ###    ###    ###     
        
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                         ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        print(f"{Fore.YELLOW}                                          ☞ O P C I O N E S ☜")
        print("\n")
        print(f"{Fore.YELLOW}                                          ☞ [1] Escaneo Normal (25400-25900)")
        print(f"{Fore.YELLOW}                                          ☞ [2] Escaneo Rapido (25565-25590)")
        print(f"{Fore.YELLOW}                                          ☞ [3] Escaneo Lento (1-65535)")
        print(f"{Fore.YELLOW}                                          ☞ [4] Escaneo Personalizado")
        print(f"{Fore.YELLOW}                                          ☞ [5] Volver al menu")
        print("\n")
        message = input(f"{Fore.WHITE} [ $ ] Seleccione su opcion >> ").replace("None", "")

        if message == "5":
            self.minecraft()

        if message == "3":
            print_lock = threading.Lock()

            ip = input(f"{Fore.YELLOW} [ $ ] Coloca la direccion de IP >> ").replace("None", "")
            port = input()
            print("\n")
            def portscan(port):
                s = socket.socke(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    con = s.connect((ip,port))
                    with print_lock:
                        server = JavaServer.lookup(ip, port)
                        status = server.status()
                        print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Direccion de IP: {Fore.YELLOW}{ip}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Puerto: {Fore.YELLOW}{port}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Jugadores Activos: {Fore.YELLOW}{status.players.online}/{status.players.max}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Version: {Fore.YELLOW}{status.version.name}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Descripcion: {Fore.YELLOW}" + re.sub(r'\ +', ' ', re.sub(r'(&|§)[a-z0-9]{1}|\n||\\n', '', ''.join([x.split('\'')[0] for x in str(status.description).split('\'text\': \'')])).replace('{', ''))+ f"\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
                    con.close()
                except:
                    pass
            
            def threader():
                while True:
                    worker = q.get()
                    portscan(worker)
                    q.task_done()

            q = Queue()

            for x in range(100):
                t = threading.Thread(ip=threader)
                t.daemon = True
                t.start()
            
            for worker in range(1,65535):
                q.put(worker)
            
            q.join()
            print("\n")
            input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            self.minecraft()

        if message == "2":
            print_lock = threading.Lock()

            ip = input(f"{Fore.YELLOW} [ $ ] Coloca la direccion de IP >> ").replace("None", "")
            print("\n")
            def portscan(port):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    con = s.connect((ip,port))
                    
                    with print_lock: ##Manda la info
                        #e3 = self.getinfo(ip, port)
                        #print(e3)
                        server = JavaServer.lookup(ip, port)
                        status = server.status()
                        print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Direccion de IP: {Fore.YELLOW}{ip}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Puerto: {Fore.YELLOW}{port}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Jugadores Activos: {Fore.YELLOW}{status.players.online}/{status.players.max}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Version: {Fore.YELLOW}{status.version.name}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Descripcion: {Fore.YELLOW}" + re.sub(r'\ +', ' ', re.sub(r'(&|§)[a-z0-9]{1}|\n||\\n', '', ''.join([x.split('\'')[0] for x in str(status.description).split('\'text\': \'')])).replace('{', ''))+ f"\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
                    con.close()
                except:
                    pass

            def threader():
                while  True:
                    worker = q.get()
                    portscan(worker)
                    q.task_done()

            q = Queue()

            for x in range(100):
                t = threading.Thread(target=threader)
                t.daemon = True
                t.start()

            for worker in range(25565,25590):
                q.put(worker)

            q.join()
            print("\n")
            input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            self.minecraft()

        if message == "1":
            print_lock = threading.Lock()

            ip = input(f"{Fore.YELLOW} [ $ ] Coloca la direccion de IP >> ").replace("None", "")
            port = input()
            print("\n")
            def portscan(port):
                s = socket.socke(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    con = s.connect((ip,port))
                    with print_lock:
                        server = JavaServer.lookup(ip, port)
                        status = server.status()
                        print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Direccion de IP: {Fore.YELLOW}{ip}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Puerto: {Fore.YELLOW}{port}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Jugadores Activos: {Fore.YELLOW}{status.players.online}/{status.players.max}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Version: {Fore.YELLOW}{status.version.name}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Descripcion: {Fore.YELLOW}" + re.sub(r'\ +', ' ', re.sub(r'(&|§)[a-z0-9]{1}|\n||\\n', '', ''.join([x.split('\'')[0] for x in str(status.description).split('\'text\': \'')])).replace('{', ''))+ f"\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
                    con.close()
                except:
                    pass
            
            def threader():
                while True:
                    worker = q.get()
                    portscan(worker)
                    q.task_done()

            q = Queue()

            for x in range(100):
                t = threading.Thread(ip=threader)
                t.daemon = True
                t.start()
            
            for worker in range(25400,25900):
                q.put(worker)
            
            q.join()
            print("\n")
            input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            self.minecraft()
    

    def nickfinder(self):
        os.system('cls')
        os.system('title Coloca el Nick de MC - KepCraft V1.0')
        banner = f"""{Fore.LIGHTBLACK_EX}
        :::    ::: :::::::::: :::::::::  :::::::::: ::::::::::: ::::    ::: :::::::::  :::::::::: :::::::::  
        :+:   :+:  :+:        :+:    :+: :+:            :+:     :+:+:   :+: :+:    :+: :+:        :+:    :+: 
        +:+  +:+   +:+        +:+    +:+ +:+            +:+     :+:+:+  +:+ +:+    +:+ +:+        +:+    +:+ 
        +#++:++    +#++:++#   +#++:++#+  :#::+::#       +#+     +#+ +:+ +#+ +#+    +:+ +#++:++#   +#++:++#:  
        +#+  +#+   +#+        +#+        +#+            +#+     +#+  +#+#+# +#+    +#+ +#+        +#+    +#+ 
        #+#   #+#  #+#        #+#        #+#            #+#     #+#   #+#+# #+#    #+# #+#        #+#    #+# 
        ###    ### ########## ###        ###        ########### ###    #### #########  ########## ###    ###
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                         ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        nick = input(f"{Fore.YELLOW} [ $ ] Coloca el nick de minecraft >> ").replace("None", "")
        
        try:
            online_uuid = requests.get('https://api.mojang.com/users/profiles/minecraft/'+ nick).json()['id']
            online_uuid_dashed = f'{online_uuid[0:8]}-{online_uuid[8:12]}-{online_uuid[12:16]}-{online_uuid[16:21]}-{online_uuid[21:32]}'
        except (KeyError, ValueError, IndexError):
            online_uuid_dashed = '-'
            online_uuid = '-'

        offline_uuid_dashed = str(uuid.UUID(bytes=hashlib.md5(bytes('OfflinePlayer:' + nick, 'utf-8')).digest()[:16], version=3))
        offline_uuid = offline_uuid_dashed.replace('-', '')
        nickname_history = {nick: '-'}
        if len(online_uuid) > 1:
            nickname_history = {}
            json_data = requests.get(f'https://api.mojang.com/user/profiles/{online_uuid}/names').json()
            for _x in json_data:
                try:
                    try:
                        date = datetime.datetime.fromtimestamp(float(_x['changedToAt'])/1000).strftime("%Y/%m/%d @ %H:%M:%S")
                    except Exception as e:
                        date = '-'
                    nickname_history[_x['name']] = date
                except:
                    pass
        print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Nickname: {Fore.YELLOW}{nick}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}UUID Offline: {Fore.YELLOW}" + offline_uuid, offline_uuid_dashed + f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}UUID Premium: {Fore.YELLOW}"+ online_uuid, online_uuid_dashed +f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Historial de Nicks: {Fore.YELLOW}"+ "".join((nick, date) for nick, data in nickname_history.items()) if nickname_history != {nick: '-'} else '`-`' +f"\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
        print("\n")
        print("\n")
        input(f'{Fore.YELLOW}[ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
        self.minecraft()

        #url = "https://api.mojang.com/users/profiles/minecraft/"
        #text123 = requests.get((url)+(nick))
        #texto_json = text123.text
        #if texto_json == "":
         #   print("\n")
          #  print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Nickname: {Fore.YELLOW}{nick}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}UUID: {Fore.YELLOW}*\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Tipo de cuenta: {Fore.YELLOW}No premium" + f"\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
           # print("\n")
            #input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            #self.minecraft()
        #else:

         #   print("\n")
          #  print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Nickname: {Fore.YELLOW}{nick}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}UUID: {Fore.YELLOW}"+ str(uuid) + f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Tipo de cuenta: {Fore.YELLOW}Premium\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
           # print("\n")
           # input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            #self.minecraft()
        
        #
        #with open("db2.txt") as f:
         #       lines = f.readlines()
          #      lines = [x.strip() for x in lines]
           #     for line in lines:
            #        if nick in line:
                        #print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Nick: {Fore.YELLOW}{nick}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Direccion de IP: {Fore.YELLOW}{lines}\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
             #           print("se encontro "+ line)
              #          print("\n")
               #         input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
                #        self.minecraft()

    def infoip(self):
        os.system('cls')
        os.system('title Coloca la IP - KepCraft V1.0')
        banner = f"""{Fore.LIGHTBLACK_EX}
        :::    ::: :::::::::: :::::::::  :::::::::: ::::::::::: ::::    ::: :::::::::  :::::::::: :::::::::  
        :+:   :+:  :+:        :+:    :+: :+:            :+:     :+:+:   :+: :+:    :+: :+:        :+:    :+: 
        +:+  +:+   +:+        +:+    +:+ +:+            +:+     :+:+:+  +:+ +:+    +:+ +:+        +:+    +:+ 
        +#++:++    +#++:++#   +#++:++#+  :#::+::#       +#+     +#+ +:+ +#+ +#+    +:+ +#++:++#   +#++:++#:  
        +#+  +#+   +#+        +#+        +#+            +#+     +#+  +#+#+# +#+    +#+ +#+        +#+    +#+ 
        #+#   #+#  #+#        #+#        #+#            #+#     #+#   #+#+# #+#    #+# #+#        #+#    #+# 
        ###    ### ########## ###        ###        ########### ###    #### #########  ########## ###    ###
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                         ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        ip = input(f"{Fore.YELLOW} [ $ ] Coloca la direccion de IP (Ejemplo: 127.0.0.1) >> ").replace("None", "")

        url = ("http://ip-api.com/json/")
        response = requests.get(url + ip)
        data = response.text
        jso = json.loads(data)
        print("\n")
        print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Direccion de IP: {Fore.YELLOW}{ip}\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}ISP: {Fore.YELLOW}" +(jso["isp"]) + f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Pais: {Fore.YELLOW}" + (jso["country"]) +  f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}ZT: {Fore.YELLOW}" + (jso["timezone"]) + f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Region: {Fore.YELLOW}" +  (jso["regionName"]) + f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Codigo ZIP: {Fore.YELLOW}" + (jso["zip"]) + f"\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Ciudad: {Fore.YELLOW}" +  (jso["city"]) + f"\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
        print("\n")
        input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
        self.minecraft()

    def subdomains(self):
        subdomains0 = ["all", "net", "bypass", "rcon", "node010", "node09", "node08", "node07", "node06", "node05", "node04", "node03", "node02", "node01", "supreme", "subnormal", "fun", "aaa", "aa", "a", "kiwi", "server10", "server09", "server08", "server07", "server06", "server05", "server04", "server03", "server02", "server01", "dev", "recuperar", "dedis", "dedicado", "vote", "events", "www", "ovh-birdmc", "cpanel", "ns-vps", "d", "t", "short", "jar", "iptables", "ufw", "recuperar", "baneados", "imagenes", "samp", "social", "holo", "donaciones", "shoprp", "wow", "multicraft", "mail", "radio3", "radio2", "fr", "teamdub", "serieyt", "shop", "report", "apply", "youtube", "twitter", "st", "lost", "sg", "srvc1", "srvc1", "torneo", "serv11", "serv0", "serv10", "serv9", "serv7", "serv6", "serv5", "serv4", "serv3", "serv2", "serv1", "serv", "mcp", "paysafe", "mu", "radio", "donate", "vps03", "vps02", "vps01", "xenon", "radio", "bans", "ns2", "ns1", "donar", "radio", "new", "appeals", "reports", "translations", "marketing", "staff", "bugs", "help", "render", "foro", "ts3", "git", "analytics", "coins", "votos", "docker-main", "docker", "main", "server3", "cdn", "server2", "creativo", "yt2", "yt", "factions", "solder", "test1", "test001", "testpene", "test", "panel", "apolo", "sv3", "sv2", "sv1", "backups", "zeus", "thor", "vps", "web", "dev", "tv", "deposito", "depositos", "extra", "extras", "bungee1", "torneoyt", "hcf", "uhc5", "uhc4", "uhc3", "uhc2", "uhc1", "uhc", "dedicado5", "dedicado4", "dedicado3", "dedicado2", "ded5", "ded4", "ded3", "ded2", "ded1", "ded", "gamehitodrh", "servidor4", "webmail", "monitor", "servidor001", "servidor10", "servidor9", "servidor8", "servidor7", "servidor6", "servidor5", "servidor4", "servidor3", "hvokfcic7sm", "autodiscover", "tauchet", "hg10", "ping", "hg9", "hg8", "hg7", "hg6", "hg5", "hg4", "hg3", "hg2", "hg1", "tienda", "status", "ayuda", "playstation", "home", "job", "firewall", "rank", "mantenimiento", "beta", "pay", "private", "port", "bb", "stor", "mx5", "serieyt", "shop", "report", "apply", "youtube", "twitter", "st", "lost", "sg", "srvc1", "srvc1", "torneo", "serv11", "serv0", "serv10", "serv9", "serv7", "serv6", "serv5", "serv4", "serv3", "serv2", "serv1", "serv", "mcp", "paysafe", "mu", "radio", "donate", "vps03", "vps02", "vps01", "xenon", "radio", "bans", "ns2", "ns1", "donar", "radio", "new", "translations", "staff", "help", "render", "ts3", "git", "analytics", "coins", "votos", "docker-main", "main", "server3", "server2", "creativo", "yt2", "yt", "factions", "solder", "test1", "test001", "testpene", "test", "panel", "sv3", "sv2", "sv1",  "vps", "build", "web", "dev", "mc", "play", "sys", "node1", "node2", "node3", "node4", "node5", "node6", "node7", "node8", "node9", "node10", "node11", "node12", "node13", "node14", "node15", "node16", "node17", "node18", "node19", "node20", "node001", "node002", "node01", "node02", "node003", "sys001", "sys002", "go", "admin", "eggwars", "bedwars", "lobby1", "hub", "builder", "developer", "test", "test1", "forum", "bans", "baneos", "ts", "ts3", "sys1", "sys2", "mods", "bungee", "bungeecord", "array", "spawn", "server", "client", "api", "smtp", "s1", "s2", "s3", "s4", "server1", "server2", "jugar", "login", "mysql", "phpmyadmin", "demo", "na", "eu", "us", "es", "fr", "it", "ru", "support", "developing", "discord", "backup", "buy", "buycraft", "go", "dedicado1", "dedi", "dedi1", "dedi2", "dedi3", "minecraft", "prueba", "pruebas", "ping", "register", "stats", "store", "serie", "buildteam", "info", "host", "jogar", "proxy", "vps", "ovh", "partner", "partners", "appeal", "store-assets", "builds", "testing", "server", "pvp", "skywars", "survival", "skyblock", "lobby", "hg", "games", "sys001", "sys002", "node001", "node002", "games001", "games002", "game001", "game002", "game003", "sys001", "us72", "us1", "us2", "us3", "us4", "us5", "goliathdev", "staticassets", "rewards", "rpsrv", "ftp", "ssh", "web", "jobs", "hcf", "grafana", "vote2", "file", "sentry", "enjin", "webserver", "xen", "mco", "monitor", "servidor2", "sadre", "gamehitodrh", "ts"]
        os.system('cls')
        os.system('title Buscador de Subdominios - KepCraft V1.0')
        banner = f"""{Fore.LIGHTBLACK_EX}
        :::    ::: :::::::::: :::::::::  :::::::::   ::::::::  ::::    ::::      :::     ::::::::::: ::::    ::: 
        :+:   :+:  :+:        :+:    :+: :+:    :+: :+:    :+: +:+:+: :+:+:+   :+: :+:       :+:     :+:+:   :+: 
        +:+  +:+   +:+        +:+    +:+ +:+    +:+ +:+    +:+ +:+ +:+:+ +:+  +:+   +:+      +:+     :+:+:+  +:+ 
        +#++:++    +#++:++#   +#++:++#+  +#+    +:+ +#+    +:+ +#+  +:+  +#+ +#++:++#++:     +#+     +#+ +:+ +#+ 
        +#+  +#+   +#+        +#+        +#+    +#+ +#+    +#+ +#+       +#+ +#+     +#+     +#+     +#+  +#+#+# 
        #+#   #+#  #+#        #+#        #+#    #+# #+#    #+# #+#       #+# #+#     #+#     #+#     #+#   #+#+# 
        ###    ### ########## ###        #########   ########  ###       ### ###     ### ########### ###    #### 
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                         ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        ip = input(f"{Fore.YELLOW} [ $ ] Coloca la WEB (Ejemplo: universocraft.com) >> ").replace("None", "")
        print("\n")
        for ejecutar0 in subdomains0:
            try:
                ipserver0 = str(ejecutar0)+"."+str(ip)
                iphost0 = socket.gethostbyname(str(ipserver0))
                s = print(f"  {Fore.LIGHTCYAN_EX}[{Fore.LIGHTRED_EX}RESULTADOS{Fore.LIGHTCYAN_EX}]--{Fore.LIGHTCYAN_EX}| {Fore.LIGHTGREEN_EX}"+str(ejecutar0)+"."+str(ip)+Fore.LIGHTCYAN_EX+" | "+Fore.LIGHTCYAN_EX+""+str(iphost0))
                #s = print(f"{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}Subdominio encontrado: {Fore.YELLOW}{ip}"+ str(ejecutar0)+"."+str(ip)+"|"+str(iphost0) +f"\n{Fore.RED}|{Fore.LIGHTMAGENTA_EX}==============================={Fore.RED}|\n\n")
            except:
                pass

        print("\n")
        input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
        self.minecraft()


    def minecraft(self):
        keyauthapp = api(
        name = "kepcraft",
        ownerid = "qill8Pc8aW",
        secret = "a822b8640a94537776edb0f5306a815fc36242f48f5acfd4700025b8e4ec7804",
        version = "1.0",
        hash_to_check = self.getchecksum()
        )

        #client_id = '1044105576470282333' 
        #RPC = Presence(client_id)  
        #RPC.connect()

        #print(RPC.update(state="🔥 ➫  KepCraft V1.0", details="🤑 ➫ Logueado como: "+ keyauthapp.user_data.username, large_image="ee", buttons=[{"label": "Buy", "url": "https://discord.gg/5KSsBhwkkw"}, {"label": "Discord", "url": "https://discord.gg/5KSsBhwkkw"}], start=time.time()))

        os.system('cls') 
        os.system(f'title Menu - Logueado como: ' + keyauthapp.user_data.username + ' - KepCraft V1.0')     
        banner = f"""{Fore.LIGHTBLUE_EX}
        :::    ::: :::::::::: :::::::::   ::::::::  :::::::::      :::     :::::::::: ::::::::::: 
        :+:   :+:  :+:        :+:    :+: :+:    :+: :+:    :+:   :+: :+:   :+:            :+:     
        +:+  +:+   +:+        +:+    +:+ +:+        +:+    +:+  +:+   +:+  +:+            +:+     
        +#++:++    +#++:++#   +#++:++#+  +#+        +#++:++#:  +#++:++#++: :#::+::#       +#+     
        +#+  +#+   +#+        +#+        +#+        +#+    +#+ +#+     +#+ +#+            +#+     
        #+#   #+#  #+#        #+#        #+#    #+# #+#    #+# #+#     #+# #+#            #+#     
        ###    ### ########## ###         ########  ###    ### ###     ### ###            ###    
        """
        print(banner)
        print("\n")
        print(f"{Fore.BLUE}                         ♥ Developer: NoJodas#6364 | Email: discordnojodas@gmail.com ♥")
        print("\n")
        print("\n")
        print(f"{Fore.YELLOW}                                          ☞ O P C I O N E S ☜")
        print("\n")
        print(f"{Fore.YELLOW}                                          ☞ [1] PortScanner") #Listo
        print(f"{Fore.YELLOW}                                          ☞ [2] RangeScanner") #Arreglado pero algo feo xd
        #print(f"{Fore.YELLOW}                                          ☞ [3] Subdomain Search") #Arreglar
        print(f"{Fore.YELLOW}                                          ☞ [3] NickFinder") #Listo
        print(f"{Fore.YELLOW}                                          ☞ [4] InfoIP") #Listo
        print(f"{Fore.YELLOW}                                          ☞ [5] Exit") #Listo
        print("\n")
        message = input(f"{Fore.WHITE} [ $ ] Seleccione su opcion >> ").replace("None", "")

        if message == "1":
            self.scan()

        if message == "2":
            self.range()

       # if message == "3":
        #    self.subdomains()
        
        if message == "3":
            self.nickfinder()
        
        if message == "4":
            self.infoip()

        if message == "5":
            exit()

        if message != "":
            exit()
try:
    el = Minecraft()
    el.authme()
except KeyboardInterrupt:
    print('Acabas de precionar CTRL + C - Finalizando procesos y saliendo de la herramienta...')