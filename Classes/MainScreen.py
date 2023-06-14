from CategoriesScreens import *
from ProfileScreen import ProfileScreen
from FavoritesScreen import FavoritesScreen
from HistoryScreen import HistoryScreen
from ReceivedRecipesScreen import ReceivedRecipesScreen
from ShoppingListScreen import ShoppingListScreen

class MainScreen(tkinter.Toplevel):
    def __init__(self,parent,username):
        super().__init__(parent)
        self.CategoryDb=CategoryDb()
        self.RecipesDb=RecipesDb()
        self.username=username

        self.parent=parent
        # print(self.parent.parent.client_socket)
        self.geometry("600x770+20+20")
        self.title('Main Screen')
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")

        self.create_gui()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    #פונקציה מייצרת גרפיקה של המסך
    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)

        self.entry_search = Entry(self.head_frame, width=80)
        self.entry_search.place(x=60, y=45)
        self.entry_search.insert(0, "Search recipe...")
        self.entry_search.config(fg="grey")

        self.recipes_box = Listbox(self, width=80)
        self.recipes_names = self.get_all_recipes_names(self.parent.parent.client_socket)



        self.entry_search.bind("<KeyRelease>", lambda event: self.search())

        self.img_search = Image.open('photos/other_photos/loupe.png')
        self.resized = self.img_search.resize((20, 18), Image.LANCZOS)
        self.image_loupe = ImageTk.PhotoImage(self.resized)
        self.btn_loupe = Button(self.head_frame, image=self.image_loupe, bd=0, bg="#658864", fg="white",
                                activebackground="#658864", activeforeground="white", command=self.open_recipe_window)
        self.btn_loupe.place(x=550, y=47)
        #_______________________________________________________________________________
        self.toogle_btn=Button(self.head_frame,text="☰",bg="#658864",fg="white",
                               font=('Bold',17),bd=0,activebackground="#658864",activeforeground="white",
                               command=self.toogle_menu)
        self.toogle_btn.pack(side=LEFT)
        self.title_lb=Label(self.head_frame,text="Tasty Pages",bg="#658864",fg="white",font=('Calibri',20))
        self.title_lb.place(x=220,y=7)
        #_______________________________________________________________________________
        self.img_appetizers=Image.open(self.get_category_image("Appetizers"))
        self.resized= self.img_appetizers.resize((150,150),Image.LANCZOS)
        self.image=ImageTk.PhotoImage(self.resized)
        self.btn_appetizers = Button(self,image=self.image,bd=0,command=self.open_appetizers_screen).place(x=100,y=150)
        self.lbl_appetizers=Label(self,text="Appetizers\nNumber of recipes: "+self.get_num_of_recipes("Appetizers"),bg="white",fg="#3C6255",
                                  width=21,font=('Calibri',10)).place(x=100,y=280)
        #_______________________________________________________________________________
        self.img_soups = Image.open(self.get_category_image("Soups"))
        self.resized = self.img_soups.resize((150, 150), Image.LANCZOS)
        self.image2 = ImageTk.PhotoImage(self.resized)
        self.btn_soups = Button(self, image=self.image2, bd=0,command=self.open_soups_screen).place(x=330, y=150)
        self.lbl_soups = Label(self, text="Soups\nNumber of recipes: "+self.get_num_of_recipes("Soups"), bg="white", fg="#3C6255",
                               width=21, font=('Calibri', 10)).place(x=330, y=280)
        #_______________________________________________________________________________
        self.img_main_dishes = Image.open(self.get_category_image("Main Dishes"))
        self.resized = self.img_main_dishes.resize((150, 150), Image.LANCZOS)
        self.image3 = ImageTk.PhotoImage(self.resized)
        self.btn_mdishes = Button(self, image=self.image3, bd=0,command=self.open_main_dishes_screen).place(x=100, y=340)
        self.lbl_mdishes = Label(self, text="Main dishes\nNumber of recipes: "+self.get_num_of_recipes("Main Dishes"), bg="white", fg="#3C6255",
                               width=21, font=('Calibri', 10)).place(x=100, y=470)
        # _______________________________________________________________________________
        self.img_salads = Image.open(self.get_category_image("Salads"))
        self.resized = self.img_salads.resize((150, 150), Image.LANCZOS)
        self.image4 = ImageTk.PhotoImage(self.resized)
        self.btn_salads = Button(self, image=self.image4, bd=0,command=self.open_salad_screen).place(x=330, y=340)
        self.lbl_salads = Label(self, text="Salads\nNumber of recipes: "+self.get_num_of_recipes("Salads"), bg="white", fg="#3C6255",
                                 width=21, font=('Calibri', 10)).place(x=330, y=470)
        # _______________________________________________________________________________
        self.img_deserts = Image.open(self.get_category_image("Deserts"))
        self.resized = self.img_deserts.resize((150, 150), Image.LANCZOS)
        self.image5 = ImageTk.PhotoImage(self.resized)
        self.btn_deserts = Button(self, image=self.image5, bd=0,command=self.open_desserts_screen).place(x=100, y=530)
        self.lbl_deserts = Label(self, text="Desserts\nNumber of recipes: "+self.get_num_of_recipes("Deserts"), bg="white", fg="#3C6255",
                                width=21, font=('Calibri', 10)).place(x=100, y=660)
        # _______________________________________________________________________________
        self.img_drinks = Image.open(self.get_category_image("Drinks"))
        self.resized = self.img_drinks.resize((150, 150), Image.LANCZOS)
        self.image6 = ImageTk.PhotoImage(self.resized)
        self.btn_drinks = Button(self, image=self.image6, bd=0,command=self.open_drinks_screen).place(x=330, y=530)
        self.lbl_drinks = Label(self, text="Drinks\nNumber of recipes: "+self.get_num_of_recipes("Drinks"), bg="white", fg="#3C6255",
                                width=21, font=('Calibri', 10)).place(x=330, y=660)
        # _______________________________________________________________________________

    #פונקציה מחפשת מתכון שהוקלד בשורת החיפוש
    def search(self):
        self.recipes_box.delete(0, END)
        self.recipes_box.lift()
        search_term = self.entry_search.get().lower()
        matching_items = [item for item in self.recipes_names if search_term in item.lower()]
        for item in matching_items:
            self.recipes_box.insert(END, item)
        if matching_items:
            self.recipes_box.place(x=self.entry_search.winfo_x(),
                                   y=self.entry_search.winfo_y() + self.entry_search.winfo_height())
        else:
            self.recipes_box.place_forget()

    #פונקציה מעבירה למסך המתכון(משורת החיפוש)
    def open_recipe_window(self):
        selected_item = self.recipes_box.get(ACTIVE)
        if selected_item:
            self.selected_item = selected_item
            print(self.selected_item)
            self.get_recipe(self.selected_item, self.parent.parent.client_socket, self.username)
        self.recipes_box.place_forget()

    #פונקציה מייצרת רשימת התפריט
    def toogle_menu(self):
        def collapse_toogle_menu():
            self.toogle_menu_fm.destroy()
            self.toogle_btn.config(text="☰")
            self.toogle_btn.config(command=self.toogle_menu)
        # __________________________________________________________________________
        self.toogle_menu_fm = Frame(self, bg="#658864")
        self.my_profile_btn=Button(self.toogle_menu_fm,text="My Profile",
                               font=("Calibri",16),bd=0,bg="#658864",fg="white",
                            activebackground="#658864",activeforeground="white",command=lambda: self.get_email(self.username,self.parent.parent.client_socket))
        self.my_profile_btn.place(x=20,y=20)
        #__________________________________________________________________________
        self.favorites_btn = Button(self.toogle_menu_fm, text="Favorites",
                                     font=("Calibri", 16), bd=0, bg="#658864", fg="white",
                                     activebackground="#658864", activeforeground="white",command=lambda: self.get_favorites(self.parent.parent.client_socket,self.username))
        self.favorites_btn.place(x=20, y=80)
        #__________________________________________________________________________
        self.history_btn = Button(self.toogle_menu_fm, text="History",
                                    font=("Calibri", 16), bd=0, bg="#658864", fg="white",
                                    activebackground="#658864", activeforeground="white",command=lambda: self.get_history(self.parent.parent.client_socket,self.username))
        self.history_btn.place(x=20, y=140)
        #__________________________________________________________________________
        self.received_recipes_btn = Button(self.toogle_menu_fm, text="Received recipes",
                                  font=("Calibri", 16), bd=0, bg="#658864", fg="white",
                                  activebackground="#658864", activeforeground="white",command=lambda: self.get_received_recipes(self.parent.parent.client_socket,self.username))
        self.received_recipes_btn.place(x=20, y=200)
        #__________________________________________________________________________
        self.shopping_list_btn = Button(self.toogle_menu_fm, text="Shopping list",
                                           font=("Calibri", 16), bd=0, bg="#658864", fg="white",
                                           activebackground="#658864", activeforeground="white",command=lambda: self.get_ingredients(self.parent.parent.client_socket))
        self.shopping_list_btn.place(x=20, y=260)
        #__________________________________________________________________________
        self.log_out_btn = Button(self.toogle_menu_fm, text="Log out",
                                        font=("Calibri", 16), bd=0, bg="#658864", fg="white",
                                        activebackground="#658864", activeforeground="white",command=lambda :self.logout())
        self.log_out_btn.place(x=20, y=320)
        #__________________________________________________________________________
        window_height = self.winfo_height()
        #__________________________________________________________________________
        self.toogle_menu_fm.place(x=0, y=70, height=window_height, width=200)
        self.toogle_btn.config(text='X')
        self.toogle_btn.config(command=collapse_toogle_menu)
        #__________________________________________________________________________

    #פונקציה מחזירה מיקומו של התמונת הקטגוריה
    def get_category_image(self, category_name):
        arr = ["get_category_image_path", category_name]
        str_get_category_image = "*".join(arr)
        self.parent.parent.send_msg(str_get_category_image, self.parent.parent.client_socket)
        image_path = self.parent.parent.recv_msg(self.parent.parent.client_socket)
        return image_path

    #פונקציה מחזירה כמות המתכונים של הקטגוריה
    def get_num_of_recipes(self,category_name):
        arr=["get_num_of_recipes",category_name]
        str_get_num_recipes = "*".join(arr)
        self.parent.parent.send_msg(str_get_num_recipes, self.parent.parent.client_socket)
        data = self.parent.parent.recv_msg(self.parent.parent.client_socket)
        arr = data.split("*")
        return arr[0]

    #פונקציה פותחת מסך הפרופיל עם כתובת המייל של המשתמש שקיבלה מהשרת
    def get_email(self, username, client_socket):
        arr = ["get_email", username]
        str_get_email = "*".join(arr)
        print(str_get_email)
        self.parent.parent.send_msg(str_get_email, client_socket)
        data = self.parent.parent.recv_msg(client_socket)
        arr = data.split("*")
        # print(arr)
        self.open_profile_screen(arr)

    #פונקציה פותחת מסך היסטוריית המתכונים עם היסטוריית המתכונים של המשתמש שקיבלה מהשרת
    def get_history(self,client_socket,username):
        arr=["get_history",username]
        str_get_history="*".join(arr)
        self.parent.parent.send_msg(str_get_history, client_socket)
        data = self.parent.parent.recv_msg(client_socket)
        arr = data.split("#")
        print(arr)
        # print("Recipe: "+arr[0])
        self.open_history_screen(arr)

    #פונקציה פותחת מסך המועדפים היסטוריית המתכונים המועדפים של המשתמש שקיבלה מהשרת
    def get_favorites(self,client_socket,username):
        arr=["get_favorites",username]
        str_get_favorites="*".join(arr)
        self.parent.parent.send_msg(str_get_favorites, client_socket)
        data = self.parent.parent.recv_msg(client_socket)
        arr = data.split("#")
        print(arr)
        # print("Recipe: "+arr[0])
        self.open_favorites_screen(arr)

    #פונקציה פותחת מסך המתכונים ששיתפו עם המשתמש עם היסטוריית המתכונים שנשלחו למשתמש שקיבלה מהשרת
    def get_received_recipes(self,client_socket,username):
        arr=["get_received_recipes",username]
        str_get_received_recipes="*".join(arr)
        self.parent.parent.send_msg(str_get_received_recipes, client_socket)
        data = self.parent.parent.recv_msg(client_socket)
        arr2 = data.split("#")
        # print(arr2)
        self.open_received_recipes_screen(arr2)

    #פונקציה מחזירה שמות של כל המתכונים
    def get_all_recipes_names(self,client_socket):
        arr=["get_all_recipes_names"]
        str_get_all_recipes_names = "*".join(arr)
        self.parent.parent.send_msg(str_get_all_recipes_names, client_socket)
        data = self.parent.parent.recv_msg(client_socket)
        arr_recipes_names = data.split("*")
        # print(arr_recipes_names)
        return arr_recipes_names

    #פונקציה פותחת מסך של המתכון עפ פרטי המתכון שקיבלה מהשרת
    def get_recipe(self, name, client_socket, username):
        check=2
        arr = ["get_one_recipe", name]
        str_get_recipe = "*".join(arr)
        # print(str_get_recipe)
        self.parent.parent.send_msg(str_get_recipe, client_socket)
        data = self.parent.parent.recv_msg(client_socket)
        arr = data.split("*")
        self.open_recipes_screen(name, arr, username,check)

    # פונקציה פותחת מסך של רשימת הקניות עם רשימת המצרכים שקיבלה מהשרת
    def get_ingredients(self,client_socket):
        arr=["get_ingredients_by_username",self.username]
        str_get_ingredients="*".join(arr)
        self.parent.parent.send_msg(str_get_ingredients, client_socket)
        data = self.parent.parent.recv_msg(client_socket)
        # print(data)
        arr2 = data.split("#")
        self.open_shopping_list_screen(arr2)

    #פונקציה מעבירה למסך הקטגוריה של המתאבנים
    def open_appetizers_screen(self):
        window = AppetizersScreen(self,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך הקטגוריה של המרקים
    def open_soups_screen(self):
        window = SoupsScreen(self,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך הקטגוריה של המנות עיקריות
    def open_main_dishes_screen(self):
        window = MainDishesScreen(self,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך הקטגוריה של הסלטים
    def open_salad_screen(self):
        window = SaladsScreen(self,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך הקטגוריה של הקינוחים
    def open_desserts_screen(self):
        window = DessertsScreen(self,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך הקטגוריה של המשקאות
    def open_drinks_screen(self):
        window = DrinksScreen(self,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך הפרופיל של המשתמש
    def open_profile_screen(self,email):
        window = ProfileScreen(self,self.username,email)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך המועדפים
    def open_favorites_screen(self,arr):
        window = FavoritesScreen(self,arr,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך ההיסטוריה של המתכונים
    def open_history_screen(self,arr):
        window = HistoryScreen(self,arr,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך המתכונים ששיתפו עם המשתמש
    def open_received_recipes_screen(self,arr):
        window = ReceivedRecipesScreen(self,arr,self.username)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך הרשימה של הקניות
    def open_shopping_list_screen(self,arr):
        window = ShoppingListScreen(self,self.username,arr)
        window.grab_set()
        self.withdraw()

    #פונקציה מעבירה למסך המתכון
    def open_recipes_screen(self, recipe_name, data_recipe, username,check):
        window = RecipesScreen(self, recipe_name, data_recipe, username,check)
        window.grab_set()
        self.withdraw()

    #פונקציה מציגה הודעה האם משתמש רוצה לצאת מהאפליקציה וסוגרת את הצד של הקליינט
    def logout(self):
        if messagebox.askokcancel("Log out", "Do you want to log out?"):
            self.parent.parent.send_msg("log_out", self.parent.parent.client_socket)
            self.parent.parent.running = False
            self.return_back_to_start_screen()

    #פונקציה מחזירה למסך הפתיחה
    def return_back_to_start_screen(self):
        self.parent.parent.deiconify()
        self.destroy()

    #פונקציה מציגה הודעה במסך אם המשתמש רוצה לסגור את חלון אפליקציה וסוגרת את צד הלקוח
    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.parent.parent.send_msg("closed", self.parent.parent.client_socket)
            self.parent.parent.running = False
            self.destroy()
