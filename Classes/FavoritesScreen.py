from RecipesScreen import *
from tkinter import messagebox

class FavoritesScreen(tkinter.Toplevel):
    def __init__(self, parent,arr,username):
        super().__init__(parent)
        self.parent = parent
        # self.username=username
        self.geometry("600x770+20+20")
        self.title('Favorites Screen')
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        self.resizable(False, False)
        self.configure(bg="#B5D5C5")
        self.username = username

        if arr[0]=="Clear":
            self.create_gui()
            self.str = StringVar()
            message = "History of favorites is empty. No recipes have been added yet."
            self.str.set(message)
            Label(self, textvariable=self.str,background="#B5D5C5", foreground="red", font=("Calibri", 15)).place(x=60, y=130)
        else:
            new_arr = []
            for item in arr:
                new_arr.append(item.split('^'))
            # print(new_arr)
            self.arr_favorites = new_arr
            self.create_gui()
            self.create_recipes()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Favorites", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=240, y=12)
        # _____________________________________________________________________________________________________
        self.img_search = Image.open('photos/other_photos/trash_can.png')
        self.resized = self.img_search.resize((30, 30), Image.LANCZOS)
        self.image_trash_can = ImageTk.PhotoImage(self.resized)
        self.clear_btn = Button(self.head_frame, image=self.image_trash_can, bd=0, bg="#658864", fg="white",
                                activebackground="#658864", activeforeground="white",
                                command=lambda: self.clear_favorites(self.username,self.parent.parent.parent.client_socket))
        self.clear_btn.place(x=530, y=20)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def create_recipes(self):
        count = 0

        canvas = Canvas(self, bg="#B5D5C5")
        canvas.pack(side=LEFT, fill=BOTH, expand=1)

        scrollbar = Scrollbar(self, orient=VERTICAL, command=canvas.yview)
        scrollbar.pack(side=RIGHT, fill=Y)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))

        recipes_frame = Frame(canvas, bg="#B5D5C5")
        canvas.create_window((0, 0), window=recipes_frame, anchor='nw')

        while count < len(self.arr_favorites) and self.arr_favorites[count][0] is not None:
            row = count // 2
            col = count % 2

            recipe_name = self.arr_favorites[count][1]
            recipe_image = self.arr_favorites[count][2]
            cooking_time = self.arr_favorites[count][4]

            image = Image.open(recipe_image).resize((150, 150), Image.LANCZOS)
            image = ImageTk.PhotoImage(image)
            button = Button(recipes_frame, image=image, text=recipe_name + "\n" + "Cooking time: " + cooking_time, bg="white",
                            fg="#3C6255",
                            font=('Calibri', 10), bd=0,
                            command=lambda count=count: self.open_recipes_screen(recipe_name, self.arr_favorites[count],
                                                                                 self.username))
            button.config(compound='top')
            button.image = image
            if count <= 1 and count % 2 == 0:
                button.grid(row=row, column=col, padx=(90, 0), pady=(70, 10))
            elif count <= 1 and count % 2 != 0:
                button.grid(row=row, column=col, padx=(35, 0), pady=(70, 10))
            elif count > 1 and count % 2 == 0:
                button.grid(row=row, column=col, padx=(100, 15), pady=(10, 10))
            elif count > 1 and count % 2 != 0:
                button.grid(row=row, column=col, padx=(55, 20), pady=(10, 10))
            count = count + 1

    def open_recipes_screen(self, recipe_name, data_recipe, username):
        window = RecipesScreen(self, recipe_name, data_recipe, username,1)
        window.grab_set()
        self.withdraw()

    def clear_favorites(self, username, client_socket):
        arr = ["clear_favorites", username]
        str_clear = "*".join(arr)
        self.parent.parent.parent.send_msg(str_clear, client_socket)
        data = self.parent.parent.parent.recv_msg(client_socket)
        print(data)
        if data == "Favorites cleared successfully":
            messagebox.showinfo("Success", "Favorites cleared successfully.\nReset the window")
        elif data == "Clearing history of favorites failed":
            messagebox.showerror("Fail", "Try again")

    def return_back(self):
        self.parent.deiconify()
        self.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.parent.parent.parent.end_msg("closed", self.parent.parent.parent.client_socket)
            self.parent.parent.parent.running = False
            self.destroy()