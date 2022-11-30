#Thank you for using this tool created by NoJodas#6364 - Avoid touching the code a lot, so as not to have any inconvenience.

#Modules
import pip
import os
import socket
import threading
import re

try:
    import requests
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'requests'])
    os.system('cls')
    import requests

try:
    from colorama import Fore
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'colorama'])
    os.system('cls')
    from colorama import Fore

try:
    import hashlib
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'hashlib'])
    os.system('cls')
    import hashlib

try:
    from queue import *
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'queue'])
    os.system('cls')
    from queue import *

try:
    import uuid
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'uuid'])
    os.system('cls')
    import uuid

try:
    import json
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'json'])
    os.system('cls')
    import json

try:
    import datetime
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'datetime'])
    os.system('cls')
    import datetime

try:
    from mcstatus import JavaServer  
except ModuleNotFoundError:
    print("Oh... Te falta un modulo para poder abrir la herramienta... Lo descargare por ti!")
    pip.main(['install', 'mcstatus'])
    os.system('cls')
    from mcstatus import JavaServer

class Tool():

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
            print(f"{Fore.WHITE} [ $ ] Empezando a escanear el rango, se escaneara con puertos default (1-65535), esto puede demorar algunos minutos...")
            os.system('nmap -p 1-65535 -T5 -Pn -A -v --open --exclude-ports 21,22,53,80,81,111,3306,2022,8096 ' + rango)
            print()
            print()
            input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            self.minecraft()

       

    def scan(self):
        os.system('cls')
        os.system('title KepPort - Seleccionar Opcion - KepCraft V1.0')
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
                t = threading.Thread(target=threader)
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
                    
                    with print_lock: 
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
                t = threading.Thread(target=threader)
                t.daemon = True
                t.start()
            
            for worker in range(25400,25900):
                q.put(worker)
            
            q.join()
            print("\n")
            input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            self.minecraft()

        
        if message == "4":
            print_lock = threading.Lock()

            ip = input(f"{Fore.YELLOW} [ $ ] Coloca la direccion de IP >> ").replace("None", "")
            port1 = input(f"{Fore.YELLOW} [ $ ] Coloca el puerto inicial (Ejemplo: 25565) >> ").replace("None", "")
            port2 = input(f"{Fore.YELLOW} [ $ ] Coloca el puerto final (Ejemplo 25590) >> ").replace("None", "")
            
            
            print("\n")
            def portscan(port):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
                while  True:
                    worker = q.get()
                    portscan(worker)
                    q.task_done()

            q = Queue()

            for x in range(100):
                t = threading.Thread(target=threader)
                t.daemon = True
                t.start()

            for worker in range(int(port1),int(port2)):
                q.put(worker)

            q.join()
            print("\n")
            input(f'{Fore.YELLOW} [ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
            self.minecraft()
            ###################
    

    def nickfinder(self):
        os.system('cls')
        os.system('title KepFinder - Nick MC - KepCraft V1.0')
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
        if online_uuid == "-":
            print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}El usuario es {Fore.RED}NO PREMIUM")
        else:
            print(f"{Fore.CYAN}[ {Fore.BLUE}> {Fore.CYAN}] {Fore.GREEN}El usuario es {Fore.YELLOW}PREMIUM")
        print("\n")
        print("\n")
        input(f'{Fore.YELLOW}[ > ] {Fore.GREEN}Escaneo finalizado, pulsa {Fore.RED}ENTER {Fore.GREEN}para volver al menu').replace("None", "")
        self.minecraft()

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

    def minecraft(self):
        os.system('cls') 
        os.system(f'title Menu - NoJodas#6364 - KepCraft V1.0')     
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
        print(f"{Fore.YELLOW}                                          ☞ [1] PortScanner") 
        print(f"{Fore.YELLOW}                                          ☞ [2] RangeScanner") 
        print(f"{Fore.YELLOW}                                          ☞ [3] NickFinder") 
        print(f"{Fore.YELLOW}                                          ☞ [4] InfoIP") 
        print(f"{Fore.YELLOW}                                          ☞ [5] Exit") 
        print("\n")
        message = input(f"{Fore.WHITE} [ $ ] Seleccione su opcion >> ").replace("None", "")

        if message == "1":
            self.scan()

        if message == "2":
            self.range()
        
        if message == "3":
            self.nickfinder()
        
        if message == "4":
            self.infoip()

        if message == "5":
            exit()

        if message != "":
            exit()
try:
    el = Tool()
    el.minecraft()
except KeyboardInterrupt:
    print("\n")
    print("\n")
    print('Acabas de precionar CTRL + C - Finalizando procesos y saliendo de la herramienta...')