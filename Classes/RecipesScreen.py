import tkinter
from tkinter import *
from tkinter import ttk
from PIL import ImageTk, Image
from Db_classes import *
import textwrap
from tkinter import messagebox

class RecipesScreen(tkinter.Toplevel):
    def __init__(self,parent,recipe_name,arr_recipe,username,check):
        self.RecipesDb=RecipesDb()
        self.IngredientsDb=IngredientsDb()
        super().__init__(parent)
        self.parent=parent
        self.geometry("600x770+20+20")
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")
        #________________________________________________________________
        self.recipe_name=recipe_name
        self.arr_recipe=arr_recipe
        # print(self.arr_recipe[3])
        # self.client_socket=self.parent.parent.parent.parent.client_socket
        self.username=username

        if check==1:
            self.client_socket=self.parent.parent.parent.parent.client_socket
            self.send_m=self.parent.parent.parent.parent.send_msg
            self.recv_m=self.parent.parent.parent.parent.recv_msg
            self.runn=self.parent.parent.parent.parent.running
        elif check==2:
            self.client_socket=self.parent.parent.parent.client_socket
            self.send_m=self.parent.parent.parent.send_msg
            self.recv_m=self.parent.parent.parent.recv_msg
            self.runn=self.parent.parent.parent.running

        self.create_gui()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text=self.arr_recipe[1], bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.pack(pady=20)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)
        #_______________________________________________________________________________________________________
        self.lnl_nutrition= Label(self,text="Nutritions: ",foreground="black",bg="#B5D5C5",font=("Calibri", 14,"underline")).place(x=30,y=100)
        self.lbl_cooking_time = Label(self,text="Cooking Time: ",foreground="black",bg="#B5D5C5",font=("Calibri", 14,"underline")).place(x=30,y=150)
        self.lbl_ingredients = Label(self,text="Ingredients(tap to add to shopping list)",foreground="black",bg="#B5D5C5",font=("Calibri", 14,"underline")).place(x=30,y=190)
        self.lbl_instructions= Label(self,text="Instructions",foreground="black",bg="#B5D5C5",font=("Calibri", 14,"underline")).place(x=30,y=520)
        #________________________________________________________________________________________________________
        max_width = 80
        wrapped_text = textwrap.fill(self.arr_recipe[5], width=max_width)

        self.title(self.arr_recipe[1])
        self.img_recipe = Image.open(self.arr_recipe[2])
        self.resized = self.img_recipe.resize((190, 190), Image.LANCZOS)
        self.image_recipe = ImageTk.PhotoImage(self.resized)
        self.lbl_image = Label(self, image=self.image_recipe,bd=0).place(x=370, y=100)
        #______________________________________
        self.nutritions_text= Label(self,text=self.arr_recipe[3],foreground="black",bg="#B5D5C5",font=("Calibri", 13))
        self.nutritions_text.place(x=120,y=102)
        #______________________________________
        self.cooking_time_text=Label(self,text=self.arr_recipe[4],foreground="black",bg="#B5D5C5",font=("Calibri", 13))
        self.cooking_time_text.place(x=150,y=152)
        #______________________________________
        self.instructuons_text = Label(self, text=wrapped_text, foreground="black", bg="#B5D5C5", font=("Calibri", 12),
                                       justify="left")
        self.instructuons_text.place(x=30, y=555)
        #______________________________________
        ingredient_list = self.get_ingredients(self.client_socket)
        placeY=220
        for ingredient in ingredient_list:
            # print("Ingredient:"+ ingredient)
            self.btn_ingredients=Button(self,text=ingredient,foreground="black",bg="#B5D5C5",bd=0,font=("Calibri", 10),
                                        highlightthickness=0,activebackground="#B5D5C5", activeforeground="black",command=lambda ingredient=ingredient: self.insert_ingredient(self.client_socket,ingredient,self.username))
            self.btn_ingredients.place(x=30,y=placeY)
            placeY=placeY+25
        #________________________________________________________________________________________________________
        text1=""
        if self.check_recipe(self.client_socket)==True:
            text1="🖤"
        elif self.check_recipe(self.client_socket)==False:
            text1="🤍"

        self.btn_add_to_favorites=Button(self,text=text1,bg="#B5D5C5",activebackground="#B5D5C5",bd=0,font=("Calibri", 20),command=lambda: (toggle_symbol(self.btn_add_to_favorites),self.insert_recipe(self.arr_recipe,self.client_socket,self.username)))
        self.btn_add_to_favorites.place(x=480,y=290)
        def toggle_symbol(button):
            if button["text"] == "🤍":
                button.config(text="🖤")
            elif button["text"] == "🖤":
                messagebox.showinfo("Exists","Recipe already exists in Favorites")
        #________________________________________________________________________________________________________
        self.btn_share=Button(self,text="🔗",bg="#B5D5C5",activebackground="#B5D5C5",bd=0,font=("Calibri", 20),command=lambda :self.get_users(self.client_socket))
        self.btn_share.place(x=520,y=290)

    def get_ingredients(self, client_socket):
        arr = ["get_ingredients", self.arr_recipe[1]]
        str_get_ingredients = "*".join(arr)
        self.send_m(str_get_ingredients, client_socket)
        data = self.recv_m(client_socket)
        print(data)
        arr2 = data.split("*")
        return arr2

    def insert_recipe(self, arr, client_socket, username):
        arr = ["insert_recipe_favorites", arr[1], arr[2], arr[3], arr[4], arr[5], username]
        str_insert = "*".join(arr)
        # print(str_insert)
        self.send_m(str_insert, client_socket)
        data = self.recv_m(client_socket)
        # print(data)
        if data == "Recipe added to favorites successfully":
            return True
        else:
            return False

    def check_recipe(self,client_socket):
        arr=["check_favorite_recipe",self.recipe_name,self.username]
        str_insert = "*".join(arr)
        self.send_m(str_insert, client_socket)
        data = self.recv_m(client_socket)
        # print(data)
        if data == "Recipe already exists in table":
            return True
        elif data == "Recipe not exists in table":
            return False

    def get_users(self,client_socket):
        arr=["get_all_users",self.username]
        str_get_recipe = "*".join(arr)
        self.send_m(str_get_recipe, client_socket)
        data = self.recv_m(client_socket)
        arr2 = data.split("*")
        print(arr2)
        self.open_choose_screen(arr2)

    def insert_ingredient(self, client_socket, ingredient_name,username):
        arr = ["insert_ingredient", ingredient_name, username]
        str_insert = "*".join(arr)
        print(str_insert)
        self.send_m(str_insert, client_socket)
        data = self.recv_m(client_socket)
        # print(data)
        if data == "Ingredient added to table successfully":
            return True
        elif data=="Already exists":
            messagebox.showinfo("Exists","You already added this product to shopping list.")
            return False

    def open_choose_screen(self,arr):
        window = ChooseScreen(self,arr,self.client_socket,self.arr_recipe,self.username)
        window.grab_set()

    def return_back(self):
        self.parent.deiconify()
        self.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.send_m("closed", self.client_socket)
            self.runn = False
            self.destroy()


class ChooseScreen(tkinter.Toplevel):
    def __init__(self,parent,arr,client_socket,arr_recipe,from_username):
        super().__init__(parent)
        self.parent=parent
        self.geometry('200x100+500+300')  # set the position of the window to (x=500,y=300)
        self.resizable(False,False)
        self.configure(bg="#B5D5C5")
        self.title('Send')
        self.arr_users=arr
        self.client_socket=client_socket
        self.arr_recipe=arr_recipe
        self.from_username=from_username
        #___________________________
        self.create_gui()

    def create_gui(self):
        self.combo = ttk.Combobox(self, values=self.arr_users)
        self.combo.set("Pick an User")
        self.combo.pack(padx=5, pady=10)

        def on_button_click():
            selected_option = self.combo.get()
            # print("Selected option:", selected_option)
            self.insert_recipe(self.arr_recipe,self.client_socket,self.from_username,selected_option)

        button = Button(self, text="Send", bg="#658864",activebackground="#658864",
                            activeforeground="white",command=on_button_click)
        button.pack(padx=5, pady=5)

    def insert_recipe(self, arr, client_socket, from_username, to_username):
        arr = ["insert_recipe_to_send", arr[1], arr[2], arr[3], arr[4], arr[5],from_username,to_username]
        str_insert = "*".join(arr)
        # print(str_insert)
        self.parent.send_m(str_insert,client_socket)
        data=self.parent.recv_m(client_socket)
        # print(data)
        if data == "Recipe added to table successfully":
            messagebox.showinfo("Success","Recipe send successfully to user: "+to_username)
        elif data=="Already exists":
            messagebox.showinfo("Again","You already send this recipe to user: "+to_username)
            return False
        else:
            messagebox.showerror("Fail","Try again")



