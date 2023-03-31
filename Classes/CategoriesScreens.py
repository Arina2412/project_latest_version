from RecipesScreen import *

def create_recipes_screen(self,arr2,client_socket,username):
    frame = Frame(self,bg="#B5D5C5")
    frame.pack(padx=10, pady=10)
    #puts current index in count
    for count, (recipe_image, recipe_name) in enumerate(arr2):
        row = count // 2
        col = count % 2
        image = Image.open(recipe_image).resize((150, 150), Image.LANCZOS)
        image = ImageTk.PhotoImage(image)
        button = Button(frame, image=image, text=recipe_name, bg="white", fg="#3C6255", font=('Calibri', 10), bd=0,
                        command=lambda recipe_name=recipe_name: get_recipe(self, recipe_name, client_socket, username))
        button.config(compound='top')
        button.image = image
        if count <= 1 and count % 2 == 0:
            button.grid(row=row, column=col, padx=(10, 0), pady=(70, 10))
        elif count <= 1 and count % 2 != 0:
            button.grid(row=row, column=col, padx=(25, 0), pady=(70, 10))
        elif count > 1 and count % 2 == 0:
            button.grid(row=row, column=col, padx=(20, 15), pady=(10, 10))
        elif count > 1 and count % 2 != 0:
            button.grid(row=row, column=col, padx=(45, 20), pady=(10, 10))


def get_recipe(self,name,client_socket,username):
    arr = ["get_one_recipe", name]
    str_get_recipe = "*".join(arr)
    # print(str_get_recipe)
    client_socket.send(str_get_recipe.encode())
    data = client_socket.recv(1024)
    data=data.decode("utf-8")
    arr=data.split("*")
    open_recipes_screen(self,name,arr,username)
    # print("Length: "+str(len(arr)))
    insert_recipe(self,arr,client_socket,username)

def open_recipes_screen(self,recipe_name,data_recipe,username):
    window = RecipesScreen(self,recipe_name,data_recipe,username,1)
    window.grab_set()
    self.withdraw()

def insert_recipe(self,arr,client_socket,username):
    arr=["insert_recipe_history",arr[1],arr[2],arr[3],arr[4],arr[5],username]
    str_insert = "*".join(arr)
    # print(str_insert)
    client_socket.send(str_insert.encode())
    data = client_socket.recv(1024)
    print(data)
    if data == "Recipe added to history successfully":
        return True
    else:
        return False

def get_recipe_image(self,category_id,client_socket):
    arr = ["get_recipe_name_and_image", str(category_id)]
    str_get_recipe_name_and_image= "*".join(arr)
    client_socket.send(str_get_recipe_name_and_image.encode())
    data = client_socket.recv(1024)
    data = data.decode("utf-8")
    arr = data.split("#")
    print(arr)
    return arr

class AppetizersScreen(tkinter.Toplevel):
    def __init__(self,parent,username):
        self.RecipesDb=RecipesDb()
        super().__init__(parent)
        self.parent=parent
        # print(self.parent.parent.parent.client_socket)
        self.geometry("600x770+20+20")
        self.title('Appetizers Screen')
        self.iconbitmap('photos/other/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")

        self.create_gui()
        arr=get_recipe_image(self,1,self.parent.parent.parent.client_socket)
        self.arr_appetizers=[]
        for item in arr:
            if item:
                name,image_path = item.split("^")
                self.arr_appetizers.append((image_path,name))
        create_recipes_screen(self,self.arr_appetizers,self.parent.parent.parent.client_socket,username)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Appetizers", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=220, y=12)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def return_back(self):
        self.parent.deiconify()
        self.destroy()


class SoupsScreen(tkinter.Toplevel):
    def __init__(self,parent,username):
        self.RecipesDb=RecipesDb()
        super().__init__(parent)
        self.parent=parent
        self.geometry("600x770+20+20")
        self.title('Soups Screen')
        self.iconbitmap('photos/other/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")
        #______________________________________________________________________________________________
        self.create_gui()
        arr = get_recipe_image(self, 2, self.parent.parent.parent.client_socket)
        self.arr_soups = []
        for item in arr:
            if item:
                name, image_path = item.split("^")
                self.arr_soups.append((image_path, name))
        create_recipes_screen(self, self.arr_soups, self.parent.parent.parent.client_socket, username)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Soups", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=250, y=12)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def return_back(self):
        self.parent.deiconify()
        self.destroy()

class MainDishesScreen(tkinter.Toplevel):
    def __init__(self,parent,username):
        self.RecipesDb=RecipesDb()
        super().__init__(parent)
        self.parent=parent
        self.geometry("600x770+20+20")
        self.title('Main Dishes Screen')
        self.iconbitmap('photos/other/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")
        #______________________________________________________________________________________________
        self.create_gui()
        arr = get_recipe_image(self, 3, self.parent.parent.parent.client_socket)
        self.arr_main_dishes = []
        for item in arr:
            if item:
                name, image_path = item.split("^")
                self.arr_main_dishes.append((image_path, name))
        create_recipes_screen(self,self.arr_main_dishes,self.parent.parent.parent.client_socket,username)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Main Dishes", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=220, y=12)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def return_back(self):
        self.parent.deiconify()
        self.destroy()

class SaladsScreen(tkinter.Toplevel):
    def __init__(self,parent,username):
        self.RecipesDb=RecipesDb()
        super().__init__(parent)
        self.parent=parent
        self.geometry("600x770+20+20")
        self.title('Salads Screen')
        self.iconbitmap('photos/other/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")
        #______________________________________________________________________________________________
        self.create_gui()
        arr = get_recipe_image(self, 4, self.parent.parent.parent.client_socket)
        self.arr_salads = []
        for item in arr:
            if item:
                name, image_path = item.split("^")
                self.arr_salads.append((image_path, name))
        create_recipes_screen(self,self.arr_salads,self.parent.parent.parent.client_socket,username)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Salads", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=250, y=12)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def return_back(self):
        self.parent.deiconify()
        self.destroy()

class DessertsScreen(tkinter.Toplevel):
    def __init__(self,parent,username):
        self.RecipesDb=RecipesDb()
        super().__init__(parent)
        self.parent=parent
        self.geometry("600x770+20+20")
        self.title('Desserts Screen')
        self.iconbitmap('photos/other/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")
        #______________________________________________________________________________________________
        self.create_gui()
        arr = get_recipe_image(self, 5, self.parent.parent.parent.client_socket)
        self.arr_desserts = []
        for item in arr:
            if item:
                name, image_path = item.split("^")
                self.arr_desserts.append((image_path, name))
        create_recipes_screen(self,self.arr_desserts,self.parent.parent.parent.client_socket,username)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Desserts", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=250, y=12)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def return_back(self):
        self.parent.deiconify()
        self.destroy()

class DrinksScreen(tkinter.Toplevel):
    def __init__(self,parent,username):
        self.RecipesDb=RecipesDb()
        super().__init__(parent)
        self.parent=parent
        self.geometry("600x770+20+20")
        self.title('Drinks Screen')
        self.iconbitmap('photos/other/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")
        #______________________________________________________________________________________________
        self.create_gui()
        arr = get_recipe_image(self, 6, self.parent.parent.parent.client_socket)
        self.arr_drinks = []
        for item in arr:
            if item:
                name, image_path = item.split("^")
                self.arr_drinks.append((image_path, name))
        create_recipes_screen(self,self.arr_drinks,self.parent.parent.parent.client_socket,username)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Drinks", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=250, y=12)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def return_back(self):
        self.parent.deiconify()
        self.destroy()
