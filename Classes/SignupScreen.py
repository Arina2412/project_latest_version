import tkinter
from tkinter import *
from tkinter import messagebox
from Db_classes import *
from PIL import ImageTk, Image
from MainScreen import MainScreen


class SignupScreen(tkinter.Toplevel):
    def __init__(self,parent):
        super().__init__(parent)
        self.parent=parent
        self.geometry("600x770+20+20")
        self.title('SignUp Screen')
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        self.resizable(False, False)
        self.UserDb=UsersDb()
        self.create_gui()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    #פונקציה מייצרת גרפיקה של המסך
    def create_gui(self):
        self.canvas = Canvas(self, width=600, height=770, bd=0, highlightthickness=0)
        self.canvas.pack()
        self.img = Image.open('photos/other_photos/background.png')
        self.resized = self.img.resize((600, 770), Image.LANCZOS)
        self.image = ImageTk.PhotoImage(self.resized)
        self.photo = self.canvas.create_image(0, 0, anchor=NW, image=self.image)
        #________________________________________________________________________________________________________
        self.canvas.create_text(300, 200,text="Sign Up",fill="#658864",font=("Calibri",38,"bold"))
        # ________________________________________________________________________________________________________
        self.lblEmailSignup = self.canvas.create_text(125,276,text="Email",fill="black",font=("Calibri", 15))
        self.entryEmailSignup1 = Entry(self, width=70)
        self.entryEmailSignup1.place(x=100, y=290)
        # self.entryEmailSignup1.insert(0, "Enter your email...")
        # self.entryEmailSignup1.config(fg="grey")
        # ________________________________________________________________________________________________________
        self.lblUsernameSignup = self.canvas.create_text(140,346,text="Username",fill="black",font=("Calibri", 15))
        self.entryUsernameSignup1 = Entry(self, width=70)
        self.entryUsernameSignup1.place(x=100, y=360)
        # self.entryUsernameSignup1.insert(0, "Enter your username...")
        # self.entryUsernameSignup1.config(fg="grey")
        # ________________________________________________________________________________________________________
        self.lblPasswordSignup = self.canvas.create_text(140,426,text="Password",fill="black",font=("Calibri", 15))
        self.entryPasswordSignup1 = Entry(self, width=70)
        self.entryPasswordSignup1.place(x=100, y=440)
        # self.entryPasswordSignup1.insert(0, "Enter your password...")
        # self.entryPasswordSignup1.config(fg="grey")
        # ________________________________________________________________________________________________________
        self.buttonAddUserSignup = Button(self, text="Sign Up", background="#C27664", foreground="white", font=("Calibri", 17),
                                          activebackground="#C27664", activeforeground="white",command=self.signup_user)
        self.buttonAddUserSignup.place(x=230, y=550, width=140, height=50)
        # ________________________________________________________________________________________________________
        self.buttonReturnToStartScreen2 = Button(self, text='Return Back', background="#C27664", foreground="white",
                                                 font=("Calibri", 14),activebackground="#C27664", activeforeground="white", command=self.return_back)
        self.buttonReturnToStartScreen2.place(x=245, y=620)
        # ________________________________________________________________________________________________________
        self.str = StringVar()
        self.str.set("")
        self.lbl_answer = self.canvas.create_text(280, 530, text=self.str.get(), fill="red", font=("Calibri", 15))

    #פונקציה שולחת פרטי המשתמש לשרת ורושמת את המשתמש למערכת
    def signup_user(self):
        if len(self.entryEmailSignup1.get()) == 0 or len(self.entryUsernameSignup1.get())==0 or len(self.entryPasswordSignup1.get()) == 0 :
            messagebox.showerror("Error", "Please write your email,username and password")
            return
        # print("signup")
        arr = ["signup", self.entryEmailSignup1.get(), self.entryUsernameSignup1.get(), self.entryPasswordSignup1.get()]
        str_insert = "*".join(arr)
        print(str_insert)
        self.parent.send_msg(str_insert,self.parent.client_socket,"encrypted")
        data=self.parent.recv_msg(self.parent.client_socket)
        print(data)
        if data == "Signed up successfully":
            self.open_main_screen()
        elif data == "Already exists":
            message = "Looks like you already have account\n Log in Please"
            self.str.set(message)
            self.canvas.itemconfig(self.lbl_answer, text=self.str.get())
        else:
            message = "Please Try Again"
            self.str.set(message)
            self.canvas.itemconfig(self.lbl_answer, text=self.str.get())
            # print(self.str.get())

    # פונקציה מעבירה למסך הראשי
    def open_main_screen(self):
        window = MainScreen(self,self.entryUsernameSignup1.get())
        window.grab_set()
        self.withdraw()

    #פונקציה מחזירה למסך הקודם
    def return_back(self):
        self.parent.deiconify()
        self.destroy()

    #פונקציה מציגה הודעה במסך אם המשתמש רוצה לסגור את חלון האפליקציה וסוגרת את צד הלקוח
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.parent.send_msg("closed", self.parent.client_socket)
            self.parent.running = False
            self.destroy()



