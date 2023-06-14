import socket
import threading
from Db_classes import *
import ast
import pickle
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


SIZE = 10 #number of digits that represent the length of a message that being sent

class Server(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.running = True
        self.FORMAT = 'utf-8'
        self.count = 0
        self.UserDb = UsersDb()
        self.CategoryDb = CategoryDb()
        self.RecipesDb = RecipesDb()
        self.IngredientsDb = IngredientsDb()
        self.HistoryRecipesDb = HistoryRecipesDb()
        self.FavoritesRecipesDb = FavoritesRecipesDb()
        self.SendReceiveRecipesDb = SendReceiveRecipesDb()
        self.ShoppingListDb = ShoppingListDb()
        key_pair = RSA.generate(2048)
        self.public_key = key_pair.publickey().export_key()
        self.private_key = key_pair.export_key()

    #פונקציה מייצרת סוקט
    def start(self):
        try:
            print('Server starting up on ip %s port %s' % (self.ip, self.port))
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.ip, self.port))
            self.sock.listen(0)  # socket will queue up as many incoming connections as the system allows

            # file_out = open("public_key","wb")
            # file_out.write(public_key)
            # file_out.close()

            while True:
                print(' Waiting for a new client')
                clientSocket, client_addresses = self.sock.accept()
                print('New client entered')
                self.send_msg(self.public_key,clientSocket)
                self.recv_msg(clientSocket)
                self.count += 1
                print(self.count)
                self.handleClient(clientSocket, client_addresses)
        except socket.error as e:
            print(e)

    #פונקציה מייצרת טרד
    def handleClient(self, clientSock,adresses):
        client_handler = threading.Thread(target=self.handle_client_connection, args=(clientSock,adresses, ))
        client_handler.start()

    #פונקציה מצפינה את ההודעה
    def encrypt(self, data):
        try:
            public_key = RSA.import_key(self.public_key) # Imports the public key from a string representation
            cipher = PKCS1_OAEP.new(public_key) # Creates a cipher object for encryption using the public key
            encrypted_data = cipher.encrypt(data) # Encrypts the data using the cipher
            return encrypted_data
        except:
            print("Fail encryption")
            return False

    #פונקציה מפענחת את ההודעה
    def decrypt(self, encrypted_data):
        try:
            private_key = RSA.import_key(self.private_key) # Import the private key from a string representation
            cipher = PKCS1_OAEP.new(private_key) # Create a cipher object for decryption using the private key
            decrypted_data = cipher.decrypt(encrypted_data) # Decrypt the encrypted data using the cipher
            return decrypted_data
        except:
            print("Fail decryption")
            return False

    #פונקציה ששולחת הודעה
    def send_msg(self, data, client_socket, m_type="string"):
        try:
            print("The message is: " + str(data))

            if type(data) != bytes and type(data) != list:
                data = data.encode() # converting the data from a string to bytes
            if m_type == "encrypted":
                encrypted_data = self.encrypt(data)
                msg = b"encrypted" + encrypted_data
                print(msg)
            elif m_type == "list":
                # print(type(data))
                msg = pickle.dumps(data) # Serialize the data using pickle(byte stream representation)
                print(msg)
            else:
                msg = data

            length = str(len(msg)).zfill(SIZE)
            length = length.encode(self.FORMAT) #convert string to bytes using UTF-8 encoding
            print(length)
            message = length + msg
            print("Message with length is: " + str(message))
            client_socket.send(message)
        except:
            print("Error with sending msg")


    #פונקציה שמקבלת הודעה
    def recv_msg(self, client_socket, m_type="string"):
        try:
            print("Receiving_________________")
            length = client_socket.recv(SIZE).decode(self.FORMAT) #decodes the received bytes to a string using UTF-8 encoding
            if not length:
                print("No length!")
                return None
            print("The length is " + length)
            data = client_socket.recv(int(length))
            if not data:
                print("No data")
                return None
            print("Data: " + str(data))
            if data.startswith(b"encrypted"):
                encrypted_data = data[len(b"encrypted"):]
                decrypted_data = self.decrypt(encrypted_data)
                return decrypted_data.decode(self.FORMAT)
            else:
                if m_type == "string":
                    return data.decode(self.FORMAT)
                else:
                    return data
        except Exception as e:
            print("Error with message receiving:", str(e))
            return None

    def handle_client_connection(self, client_socket,adress):
        not_crash = True
        # print(not_crash)
        while self.running:
            while not_crash:
                try:
                    print(adress)
                    server_data=self.recv_msg(client_socket)
                    print(server_data)
                    arr=server_data.split("*")
                    print(arr)
                    #בקשה להירשם עם פרטי ההרשמה שהמשתמש הזין
                    if arr!=None and arr[0]=="signup" and len(arr)==4:
                        server_data=self.UserDb.insert_user(arr[1],arr[2],arr[3])
                        print("Server data: ",server_data)
                        if server_data==True:
                            print(server_data)
                            self.send_msg("Signed up successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Sign up failed",client_socket)
                        elif server_data=="Exists":
                            self.send_msg("Already exists",client_socket)
                    #_____________________________________________בקשה לבדוק אם המשתמש קיים במסד הנתונים
                    elif arr!=None and arr[0]=="login" and len(arr)==3:
                        # print("Login user")
                        # print(arr)
                        server_data = self.UserDb.check_user(arr[1],arr[2])
                        print("Server data: ", server_data)
                        if server_data==True:
                            print(server_data)
                            self.send_msg("Loged In successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Wrong password",client_socket)
                        elif server_data=="Fail":
                            self.send_msg("Login failed",client_socket)
                    # _____________________________________________בקשה להחזיר מיקום של התמונת הקטגוריה
                    elif arr != None and arr[0] == "get_category_image_path" and len(arr) == 2:
                        image_path = self.CategoryDb.get_image_path(arr[1])
                        if image_path == "Category is not found in the table":
                            self.send_msg("Search for category image failed", client_socket)
                        else:
                            self.send_msg(image_path,client_socket)
                    # _____________________________________________בקשה להחזיר כמות המתכונים של הקטגוריה מסוימת
                    elif arr!=None and arr[0]=="get_num_of_recipes" and len(arr)==2:
                        server_data=self.CategoryDb.get_num_of_recipes(arr[1])
                        # print("Server data: ", server_data)
                        if server_data:
                            self.send_msg(server_data,client_socket)
                        elif server_data=="Category is not found in the table":
                            self.send_msg("Search for num of recipes failed",client_socket)
                     # _____________________________________________בקשה להחזיר כל השמות של כל המתכונים
                    elif arr != None and arr[0] == "get_all_recipes_names" and len(arr) == 1:
                        server_data = self.RecipesDb.get_recipe_names()
                        # print("Server data: ", server_data)
                        arr_to_send = "*".join(server_data)
                        # print(arr_to_send)
                        if server_data:
                            self.send_msg(arr_to_send,client_socket)
                        elif server_data == "No recipes in the table":
                            self.send_msg("No recipes found",client_socket)
                    # _____________________________________________בקשה להחזיר את פרטי המתכון
                    elif arr!= None and arr[0] == "get_one_recipe" and len(arr) == 2:
                        # print(arr)
                        server_data=self.RecipesDb.get_one_recipe(arr[1])
                        print(server_data)
                        arr_to_send= "*".join(server_data)
                        print(arr_to_send)
                        if server_data:
                            self.send_msg(arr_to_send,client_socket)
                        elif server_data:
                            self.send_msg("Search for recipe failed",client_socket)
                    #______________________________________________בקשה להחזיר שם ומיקום התמונה של המתכונים השייכים לקטגוריה מסוימת
                    elif arr != None and arr[0] == "get_recipe_name_and_image_path" and len(arr) == 2:
                        server_data = self.RecipesDb.get_name_and_image_by_ctg_id(arr[1])
                        print("Server data: ", server_data)
                        if server_data:
                            arr_to_send = "#".join(server_data)
                            print(arr_to_send)
                            self.send_msg(arr_to_send, client_socket)
                    #בקשה להחזיר שם ומידע של התמונה של המתכונים השייכים לקטגוריה מסוימת
                    elif arr != None and arr[0] == "get_recipe_name_and_image_data" and len(arr) == 2:
                        server_data = self.RecipesDb.get_name_and_image_by_ctg_id(arr[1])
                        image_paths = [s.split('^')[1] for s in server_data]
                        for path in image_paths:
                            with open(path, 'rb') as f:
                                data = f.read()
                                self.send_msg(data, client_socket)
                    # _____________________________________________בקשה להחזיר כל המצרכים השייכים למתכון מסוים
                    elif arr!=None and arr[0]=="get_ingredients" and len(arr)==2:
                        server_data=self.IngredientsDb.get_ingredients_by_recipe_name(arr[1])
                        # print("Server data: ", server_data)
                        arr_to_send = "*".join(server_data)
                        if server_data:
                            self.send_msg(arr_to_send,client_socket)
                        elif arr_to_send[0]=="No ingredients":
                            self.send_msg("No ingredients exist",client_socket)
                    # _____________________________________________קשה להחזיר פרטי הכתובת מייל של המשתמש
                    elif arr!= None and arr[0] == "get_email" and len(arr) == 2:
                        # print(arr)
                        server_data=self.UserDb.get_email_by_name(arr[1])
                        # print("Server data: ",server_data)
                        if server_data:
                            self.send_msg(server_data,client_socket)
                        elif server_data:
                            self.send_msg("Search for email failed",client_socket)
                    # _____________________________________________בקשה לשנות/לעדכן כתובת המייל של המשתמש
                    elif arr!=None and arr[0]=="change_email" and len(arr)==3:
                        # print(arr)
                        server_data=self.UserDb.update_email(arr[1],arr[2])
                        # print("Server data: ",server_data)
                        if server_data==True:
                            print(server_data)
                            self.send_msg("Email changed successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Changing email failed",client_socket)
                    # _____________________________________________בקשה לשנות/לעדכן סיסמא של המשתמש
                    elif arr!=None and arr[0]=="change_password" and len(arr)==3:
                        print(arr)
                        server_data=self.UserDb.update_password(arr[1],arr[2])
                        # print("Server data: ",server_data)
                        if server_data==True:
                            print(server_data)
                            self.send_msg("Password changed successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Changing password failed",client_socket)
                        elif server_data=="Fail,user doesn't exist":
                            self.send_msg("User doesn't exist in table",client_socket)
                    # _____________________________________________בקשה להכניס מתכון לטבלה של היסטוריית המתכונים
                    elif arr!=None and arr[0] == "insert_recipe_history" and len(arr)==7:
                        print(arr)
                        server_data=self.HistoryRecipesDb.insert_recipe(arr[1],arr[2],arr[3],arr[4],arr[5],arr[6])
                        # print("Server data: ", server_data)
                        if server_data==True:
                            print(server_data)
                            self.send_msg("Recipe added to history successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Already exists",client_socket)
                    # _____________________________________________בקשה לנקות/למחוק את כל המתכונים מההיסטורית המתכונים
                    elif arr != None and arr[0] == "clear_history" and len(arr) == 2:
                        username = arr[1]
                        print(username)
                        server_data = self.HistoryRecipesDb.delete_all_recipes(username)
                        # print("Server data: ", server_data)
                        if server_data==True:
                            self.send_msg("History cleared successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Clearing history failed",client_socket)
                    #בקשה למחוק חלק מהמתכונים מההיסטוריית המתכונים
                    elif arr != None and arr[0] == "clear_few_recipes" and len(arr) == 3:
                        server_data = self.HistoryRecipesDb.delete_few_recipes(arr[1],arr[2])
                        # print("Server data: ", server_data)
                        if server_data==True:
                            self.send_msg("Recipes deleted successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Deleting recipes failed",client_socket)
                    # _____________________________________________בקשה להחזיר את כל המתכונים מהיסטוריית המתכונים השייכים למשתמש
                    elif arr!=None and arr[0]=="get_history" and len(arr)==2:
                        server_data=self.HistoryRecipesDb.get_all_recipes(arr[1])
                        # print("Server data: ", server_data)
                        if server_data == 0:
                            arr = []
                            info="Clear"
                            arr = info.split("#")
                            arr_to_send = "#".join(arr)
                            # print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                        else:
                            arr_to_send = "#".join(server_data)
                            # print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                    # _____________________________________________בקשה להכניס מתכון לטבלת המועדפים
                    elif arr!=None and arr[0] == "insert_recipe_favorites" and len(arr)==7:
                        # print(arr)
                        server_data=self.FavoritesRecipesDb.insert_recipe(arr[1],arr[2],arr[3],arr[4],arr[5],arr[6])
                        # print("Server data: ", server_data)
                        if server_data==True:
                            print(server_data)
                            self.send_msg("Recipe added to favorites successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Already exists",client_socket)
                    # _____________________________________________בקשה לנקות/למחוק את כל המתכונים ממועדפים
                    elif arr != None and arr[0] == "clear_favorites" and len(arr) == 2:
                        # print(arr)
                        username = arr[1]
                        # print(username)
                        server_data = self.FavoritesRecipesDb.delete_all_recipes(username)
                        print("Server data: ", server_data)
                        if server_data==True:
                            self.send_msg("Favorites cleared successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Clearing history of favorites failed",client_socket)
                    # _____________________________________________בקשה להחזיר את כל המתכונים ממועדפים השייכים למשתמש
                    elif arr!=None and arr[0]=="get_favorites" and len(arr)==2:
                        server_data=self.FavoritesRecipesDb.get_all_recipes(arr[1])
                        # print("Server data: ", server_data)
                        if server_data == 0:
                            arr = []
                            info="Clear"
                            arr = info.split("#")
                            arr_to_send = "#".join(arr)
                            # print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                        else:
                            arr_to_send = "#".join(server_data)
                            print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                    # _____________________________________________בקשה לבדוק אם המתכון קיים במועדפים
                    elif arr!=None and arr[0]=="check_favorite_recipe" and len(arr)==3:
                        server_data=self.FavoritesRecipesDb.check_recipe(arr[1],arr[2])
                        # print("Server data: ", server_data)
                        if server_data==True:
                            self.send_msg("Recipe already exists in table",client_socket)
                        elif server_data==False:
                            self.send_msg("Recipe not exists in table",client_socket)
                    # _____________________________________________בקשה להחזיר רשימה של כל המשתמשים
                    elif arr!=None and arr[0]=="get_all_users" and len(arr)==2:
                        server_data=self.UserDb.get_all_users(arr[1])
                        # print("Server data: ", server_data)
                        arr_to_send = "*".join(server_data)
                        if server_data:
                            self.send_msg(arr_to_send,client_socket)
                        elif server_data=="No users":
                            self.send_msg("No users exist",client_socket)
                    # _____________________________________________בקשה להכניס מתכון לטבלת המתכונים ששותפו עם המשתמש
                    elif arr!=None and arr[0] == "insert_recipe_to_send" and len(arr)==8:
                        # print(arr)
                        server_data=self.SendReceiveRecipesDb.insert_recipe(arr[1],arr[2],arr[3],arr[4],arr[5],arr[6],arr[7])
                        # print("Server data: ", server_data)
                        if server_data==True:
                            print(server_data)
                            self.send_msg("Recipe added to table successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Already exists",client_socket)
                    # _____________________________________________בקשה להחזיר את כל המתכונים ששותפו עם המשתמש
                    elif arr!=None and arr[0]=="get_received_recipes" and len(arr)==2:
                        server_data=self.SendReceiveRecipesDb.get_all_recipes(arr[1])
                        # print("Server data: ", server_data)
                        if server_data == 0:
                            arr = []
                            info="Clear"
                            arr = info.split("#")
                            arr_to_send = "#".join(arr)
                            # print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                        else:
                            arr_to_send = "#".join(server_data)
                            print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                    # _____________________________________________בקשה לנקות/למחוק את כל המתכונים ששותפו עם המשתמש
                    elif arr != None and arr[0] == "clear_received_recipes" and len(arr) == 2:
                        # print(arr)
                        username = arr[1]
                        server_data = self.SendReceiveRecipesDb.delete_all_recipes(username)
                        print("Server data: ", server_data)
                        if server_data==True:
                            self.send_msg("Received recipes cleared successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Clearing history of received recipes failed",client_socket)
                    # _____________________________________________בקשה להכניס מצרך לרשימת הקניות
                    elif arr!=None and arr[0]=="insert_ingredient" and len(arr)==3:
                        server_data=self.ShoppingListDb.insert_ingredient(arr[1],arr[2])
                        print("Server data: ", server_data)
                        if server_data == True:
                            print(server_data)
                            self.send_msg("Ingredient added to table successfully",client_socket)
                        elif server_data == False:
                            self.send_msg("Already exists",client_socket)
                    # _____________________________________________בקשה להחזיר את כל המצרכים מהרשימת קניות השייכים למשתמש
                    elif arr!=None and arr[0]=="get_ingredients_by_username" and len(arr)==2:
                        server_data=self.ShoppingListDb.get_ingredients_by_username(arr[1])
                        print("Server data: ", server_data)
                        if server_data == 0:
                            arr = []
                            info = "Clear"
                            arr = info.split("#")
                            arr_to_send = "#".join(arr)
                            # print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                        else:
                            arr_to_send = "#".join(server_data)
                            print(arr_to_send)
                            self.send_msg(arr_to_send,client_socket)
                    # _____________________________________________בקשה למחוק מצרכים מהרשימת קניות שהמשתמש מסוים
                    elif arr != None and arr[0] == "clear_shopping_list" and len(arr) == 3:
                        arr_ingredients=ast.literal_eval(arr[1])# converts from string to actial objects
                        server_data = self.ShoppingListDb.delete_ingredients_by_name_and_username(arr_ingredients,arr[2])
                        print("Server data: ", server_data)
                        if server_data==True:
                            self.send_msg("Shopping list cleared successfully",client_socket)
                        elif server_data==False:
                            self.send_msg("Clearing shopping list failed",client_socket)
                    # _____________________________________________הודעה שהמשתמש יצא מהאפליקציה
                    elif arr!=None and arr[0]=="log_out" and len(arr)==1:
                        print(f"Client {adress} logged out.")
                        break
                    #הודעה שהמשתמש סגר את האפליקציה
                    elif arr!= None and arr[0] == "closed" and len(arr) == 1:
                        print(f"Client {adress} closed the connection.")
                        break
                except:
                    print("Error")
                    not_crash=False
                    break


if __name__ == '__main__':
   # ip = '0.0.0.0'
   # port = 5010
   ip = input("Enter IP: ")
   port = input("Enter port: ")
   S = Server(ip, int(port))
   S.start()