from RecipesScreen import *
from tkinter import messagebox

class ReceivedRecipesScreen(tkinter.Toplevel):
    def __init__(self, parent,arr,username):
        super().__init__(parent)
        self.parent = parent

        self.geometry("600x770+20+20")
        self.title('Received Recipes Screen')
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        self.resizable(False, False)
        self.configure(bg="#B5D5C5")
        #______________________________
        self.username=username

        if arr[0]=="Clear":
            self.create_gui()
            self.str = StringVar()
            message = "History of received recipes is empty. No recipes have been received yet."
            self.str.set(message)
            Label(self, textvariable=self.str,background="#B5D5C5", foreground="red", font=("Calibri", 13)).place(x=40, y=130)
        else:
            new_arr = []
            for item in arr:
                new_arr.append(item.split('^'))
            # print(new_arr)
            self.arr_received_recipes = new_arr
            self.create_gui()
            self.create_recipes_screen()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    #פונקציה מייצרת גרפיקה של המסך
    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Received Recipes", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=220, y=12)
        # _____________________________________________________________________________________________________
        self.img_search = Image.open('photos/other_photos/trash_can.png')
        self.resized = self.img_search.resize((30, 30), Image.LANCZOS)
        self.image_trach_can = ImageTk.PhotoImage(self.resized)
        self.clear_btn = Button(self.head_frame, image=self.image_trach_can, bd=0, bg="#658864", fg="white",
                                activebackground="#658864", activeforeground="white",
                                command=lambda: self.clear_received_recipes(self.username, self.parent.parent.parent.client_socket))
        self.clear_btn.place(x=530, y=20)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    #פונקציה מייצרת את מסך המתכון ופותחת אותו
    def create_recipes_screen(self):
        count = 0
        btnX = 0
        btnY = 150

        while count < len(self.arr_received_recipes) and self.arr_received_recipes[count][0] is not None:
            recipe_name = self.arr_received_recipes[count][1]
            recipe_image = self.arr_received_recipes[count][2]
            cooking_time = self.arr_received_recipes[count][4]
            from_user=self.arr_received_recipes[count][6]

            # print(recipe_name)
            count = count + 1
            if count > 2 and count % 2 != 0:
                btnY += 210
            if count % 2 != 0:
                btnX = 100
            elif count % 2 == 0:
                btnX = 330
            count = count - 1
            # print(count)
            # print(self.arr_history[3])
            image = Image.open(recipe_image).resize((150, 150), Image.LANCZOS)
            image = ImageTk.PhotoImage(image)
            button = Button(self, image=image, text=recipe_name + "\n" + "From user: " + from_user, bg="white",
                            fg="#3C6255",
                            font=('Calibri', 10), bd=0,
                            command=lambda count=count: self.open_recipes_screen(recipe_name, self.arr_received_recipes[count],
                                                                                 self.username))
            button.config(compound='top')
            button.image = image
            button.place(x=btnX, y=btnY)
            count = count + 1



    #פונקציה מעבירה למסך המתכון
    def open_recipes_screen(self, recipe_name, data_recipe, username):
        window = RecipesScreen(self, recipe_name, data_recipe, username,1)
        window.grab_set()
        self.withdraw()

    #פונקציה שולחת שם המשתמש לשרת למטרת המחיקה של המתכונים בהיסטוריה המתכונים שנשלחו לו מהמשתמשים אחרים, השייכים לו
    def clear_received_recipes(self, username, client_socket):
        arr = ["clear_received_recipes", username]
        str_clear = "*".join(arr)
        self.parent.parent.parent.send_msg(str_clear, client_socket)
        data = self.parent.parent.parent.recv_msg(client_socket)
        print(data)
        if data == "Received recipes cleared successfully":
            messagebox.showinfo("Success", "History of received recipes cleared successfully.\nReset the window")
        elif data == "Clearing history of received recipes failed":
            messagebox.showerror("Fail", "Try again")

    #פונקציה מחזירה למסך הראשי
    def return_back(self):
        self.parent.deiconify()
        self.destroy()

    #פונקציה מציגה הודעה במסך אם המשתמש רוצה לסגור את חלון אפליקציה וסוגרת את צד הלקוח
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.parent.parent.parent.end_msg("closed", self.parent.parent.parent.client_socket)
            self.parent.parent.parent.running = False
            self.destroy()