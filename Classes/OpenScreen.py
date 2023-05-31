import tkinter
from tkinter import *
from PIL import ImageTk, Image
import threading
import socket
from Db_classes import *
from SignupScreen import SignupScreen
from tkinter import messagebox
from MainScreen import MainScreen

SIZE = 10

class StartScreen(tkinter.Tk):
    def __init__(self,ip,port):
        self.UserDb=UsersDb()
        super().__init__()
        self.ip = ip
        self.port = port
        self.running=True
        self.FORMAT = 'utf-8'
        self.geometry("600x770+20+20")
        self.title('Start Screen')
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        #self.configure(bg="#BCEAD5")
        self.resizable(False,False)

        self.handle_thread_socket()
        self.create_gui()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_gui(self):
        self.canvas=Canvas(self,width=600,height=770,bd=0,highlightthickness=0)
        self.canvas.pack()
        self.img = Image.open('photos/other_photos/background.png')
        self.resized = self.img.resize((600, 770), Image.LANCZOS)
        self.image = ImageTk.PhotoImage(self.resized)
        self.photo = self.canvas.create_image(0,0,anchor=NW,image=self.image)
        # ________________________________________________________________________________________________________
        self.canvas.create_text(300, 230,text="Tasty Pages",fill="#4E6C50",font=("Calibri",38,"bold"))
        # ________________________________________________________________________________________________________
        self.buttonLogin=Button(self.canvas,text='LOG IN',background="#C27664",foreground="white",font=("Calibri",18),
                                activebackground="#C27664", activeforeground="white",command=self.open_login_screen)
        self.buttonLogin.place(x=210,y=320,width=170,height=60)
        self.buttonSignup=Button(self.canvas, text='SIGN UP', background="#C27664",foreground="white",font=("Calibri",18),
                                 activebackground="#C27664", activeforeground="white",command=self.open_signup_screen)
        self.buttonSignup.place(x=210,y=400,width=170,height=60)
        # ________________________________________________________________________________________________________

    def open_login_screen(self):
        window=LoginScreen(self)
        window.grab_set()
        self.withdraw()

    def open_signup_screen(self):
        window=SignupScreen(self)
        window.grab_set()
        self.withdraw()

    def handle_thread_socket(self):
        client_handler = threading.Thread(target=self.create_socket, args=())
        client_handler.daemon = True
        client_handler.start()

    def create_socket(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.ip,self.port))
            data = self.recv_msg(self.client_socket)
            print("data: "+data)
            print("hi", self.client_socket)
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", "The server is not running yet.\nTry again later.")

    def send_msg(self, data, client_socket):
        try:
            print("Sending____________________\nMessage: " + str(data))
            if type(data) != bytes:
                data = data.encode()
            length = str(len(data)).zfill(SIZE)
            length = length.encode(self.FORMAT)
            message = length + data
            print("Message with length: " + str(message)+"\n________________________________________________")
            client_socket.send(message)
        except:
            print("Error with message sending from client")

    def recv_msg(self, client_socket, m_type="string"):
        try:
            print("Receiving_________________")
            length = client_socket.recv(SIZE).decode(self.FORMAT)
            if not length:
                print("No length")
                return None
            print("Length: " + length)
            data = client_socket.recv(int(length))
            if not data:
                print("No data")
                return None
            print("Data: " + str(data))
            if m_type == "string":
                data = data.decode(self.FORMAT)
            print("Data is:" + data)
            # if m_type == "bytes":
            #     print("Data is bytes")
            return data
        except Exception as e:
            print("Error with message receiving: ", str(e))
            error_message = "[WinError 10054] An existing connection was forcibly closed by the remote host"
            if str(e) == error_message:
                self.pops_error()
            return None

    def pops_error(self):
        messagebox.showerror("Connection Error", "The server has disconnected.\nPlease reconnect later.")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.send_msg("closed", self.client_socket)
            self.running = False
            self.destroy()

class LoginScreen(tkinter.Toplevel):
    def __init__(self,parent):
        super().__init__(parent)
        self.parent=parent

        self.geometry("600x770+20+20")
        self.title('LogIn Screen')
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        self.resizable(False, False)
        self.UserDb = UsersDb()

        self.create_gui()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_gui(self):
        self.canvas = Canvas(self, width=600, height=770, bd=0, highlightthickness=0)
        self.canvas.pack()
        self.img = Image.open('photos/other_photos/background.png')
        self.resized = self.img.resize((600, 770), Image.LANCZOS)
        self.image = ImageTk.PhotoImage(self.resized)
        self.photo = self.canvas.create_image(0, 0, anchor=NW, image=self.image)
        # ________________________________________________________________________________________________________
        self.canvas.create_text(300, 200,text="Log In",fill="#658864",font=("Calibri",38,"bold"))
        # ________________________________________________________________________________________________________
        self.lblUsernameLogin=self.canvas.create_text(135,268,text="Username",fill="black",font=("Calibri", 15))
        self.entryUsernameLogin = Entry(self, width=70)
        self.entryUsernameLogin.place(x=95, y=280)
        # ________________________________________________________________________________________________________
        self.lblPasswordLogin=self.canvas.create_text(135,368,text="Password",fill="black",font=("Calibri", 15))
        self.entryPasswordLogin = Entry(self, width=70,show="*")
        self.entryPasswordLogin.place(x=95, y=380)
        # ________________________________________________________________________________________________________
        self.buttonEnterUserLogin = Button(self, text="Log In", background="#C27664", foreground="white", font=("Calibri", 17),
                                           activebackground="#C27664", activeforeground="white",command=self.login_user)
        self.buttonEnterUserLogin .place(x=230, y=450, width=140, height=50)
        # ________________________________________________________________________________________________________
        self.buttonReturnToStartScreen = Button(self, text='Return Back', background="#C27664", foreground="white", font=("Calibri", 14),
                          activebackground="#C27664", activeforeground="white",command=self.return_back)
        self.buttonReturnToStartScreen.place(x=245, y=530)
        # ________________________________________________________________________________________________________
        self.str = StringVar()
        self.str.set("")
        self.lbl_answer = self.canvas.create_text(300, 430, text=self.str.get(), fill="red", font=("Calibri", 15))

    def login_user(self):
        if len(self.entryUsernameLogin.get())==0 or len(self.entryPasswordLogin.get())==0:
            messagebox.showerror("Error", "Please write your username and password")
            return
        arr=["login",self.entryUsernameLogin.get(),self.entryPasswordLogin.get()]
        str_check = "*".join(arr)
        print(str_check)
        self.parent.send_msg(str_check,self.parent.client_socket)
        data=self.parent.recv_msg(self.parent.client_socket)
        print(data)
        if data == "Loged In successfully":
            self.open_main_screen()
        elif data == "Wrong password":
            message = "Wrong password"
            self.str.set(message)
            self.canvas.itemconfig(self.lbl_answer, text=self.str.get())  # update canvas text object
        elif data == "Login failed":
            message = "Please Sign Up"
            self.str.set(message)
            self.canvas.itemconfig(self.lbl_answer, text=self.str.get())

    def open_main_screen(self):
        window = MainScreen(self,self.entryUsernameLogin.get())
        window.grab_set()
        self.withdraw()

    def return_back(self):
        self.parent.deiconify() #displays the window, after using the withdraw method
        self.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.parent.send_msg("closed", self.parent.client_socket)
            self.parent.running = False
            self.destroy()

if __name__ == "__main__":
    ip = input("Enter IP: ")
    port = input("Enter port: ")
    window = StartScreen(ip,int(port))
    window.mainloop()

