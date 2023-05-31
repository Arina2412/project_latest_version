import tkinter
from tkinter import *
from tkinter import messagebox
from PIL import ImageTk, Image


class ShoppingListScreen(tkinter.Toplevel):
    def __init__(self, parent,username,arr):
        super().__init__(parent)
        self.parent = parent

        self.geometry("600x770+20+20")
        self.title('Shopping List Screen')
        self.iconbitmap('photos/other_photos/icon_recipe.ico')
        self.resizable(False, False)
        self.configure(bg="#B5D5C5")
        self.username=username
        self.arr_ingredients=arr
        self.list=[]

        if self.arr_ingredients[0]=="Clear":
            self.create_gui()
            self.str = StringVar()
            message = "Shopping list is empty. No products have been added yet."
            self.str.set(message)
            Label(self, textvariable=self.str,background="#B5D5C5", foreground="red", font=("Calibri", 15)).place(x=50, y=180)
        else:
            new_arr = []
            for item in arr:
                new_arr.append(item.split('^'))
            # print(new_arr)
            self.arr_favorites = new_arr
            self.create_gui()
            self.create_shopping_list()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)


    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Shopping List", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=220, y=12)
        # _____________________________________________________________________________________________________
        self.img_search = Image.open('photos/other_photos/trash_can.png')
        self.resized = self.img_search.resize((30, 30), Image.LANCZOS)
        self.image_trach_can = ImageTk.PhotoImage(self.resized)
        self.clear_btn = Button(self.head_frame, image=self.image_trach_can, bd=0, bg="#658864", fg="white",
                                activebackground="#658864", activeforeground="white",
                                command=lambda: self.clear_shopping_list(self.list,self.username, self.parent.parent.parent.client_socket))
        self.clear_btn.place(x=530, y=20)
        # _____________________________________________________________________________________________________
        self.buy_lbl=Label(self,text="To buy:",bg="#B5D5C5",font=("Calibri",15,"underline"))
        self.buy_lbl.place(x=50,y=120)
        # _____________________________________________________________________________________________________
        self.add_entry=Entry(self,width=25,font=("Calibri",12))
        self.add_entry.place(x=300,y=125)
        self.add_entry.insert(0,"Enter product to add to list...")
        self.add_entry.config(fg="grey")
        # _____________________________________________________________________________________________________
        self.add_btn=Button(self,text="Add to list",font=("Calibri",12),bd=0,bg="#658864",fg="white",
                            activebackground="#658864", activeforeground="white",
                            command=lambda: self.insert_ingredient(self.add_entry.get(), self.parent.parent.parent.client_socket,self.username))
        self.add_btn.place(x=510,y=122)
        # _____________________________________________________________________________________________________
        self.buttonReturnToMainScreen = Button(self.head_frame, text='←', bd=0, background="#658864",
                                               foreground="white",
                                               font=("Calibri", 17), activebackground="#658864",
                                               activeforeground="white", command=self.return_back)
        self.buttonReturnToMainScreen.place(x=5, y=12)

    def create_shopping_list(self):
        count = 0
        Y = 150
        while count < len(self.arr_ingredients) and self.arr_ingredients[count][0] is not None:
            self.ingredient_name = self.arr_ingredients[count]
            ingredient_btn = Button(self, text=self.ingredient_name, bd=0, bg="#B5D5C5", activebackground="#B5D5C5",
                                    activeforeground="white", font=("Calibri", 13))
            ingredient_btn.config(
                command=lambda current=ingredient_btn, ingredient=self.ingredient_name: self.add_to_overstrike(current, ingredient))
            ingredient_btn.place(x=50, y=Y)
            count = count + 1
            Y = Y + 25

    def change_font(self, current):
        current.config(font=("Calibri", 13, 'overstrike'))

    def add_to_overstrike(self, ingredient_btn, ingredient):
        if ingredient not in self.list:
            self.list.append(ingredient)
            ingredient_btn.config(font=("Calibri", 13, 'overstrike'))
            return True  # ingredient is not exist in the list
        else:
            self.list.remove(ingredient)
            ingredient_btn.config(font=("Calibri", 13))
            return False  # ingredient is exist in the list

    def clear_shopping_list(self, arr_to_delete, username, client_socket):
        arr = ["clear_shopping_list", str(arr_to_delete), username]
        print(arr)
        str_clear = "*".join(arr)
        self.parent.parent.parent.send_msg(str_clear, client_socket)
        data = self.parent.parent.parent.recv_msg(client_socket)
        print(data)
        if data == "Shopping list cleared successfully":
            messagebox.showinfo("Success", "Chosen products cleared successfully.\nReset the window")
        elif data == "Clearing products failed":
            messagebox.showerror("Fail", "Try again")

    def insert_ingredient(self,ingredient,client_socket,username):
        arr = ["insert_ingredient", ingredient, username]
        str_insert = "*".join(arr)
        print(str_insert)
        self.parent.parent.parent.send_msg(str_insert, client_socket)
        data = self.parent.parent.parent.recv_msg(client_socket)
        if data == "Ingredient added to table successfully":
            messagebox.showinfo("Success","Product added to list successfully.\nReset the window")
        elif data=="Already exists":
            messagebox.showinfo("Exists","Product already exists in the list")
        else:
            messagebox.showerror("Fail", "Try again")


    def return_back(self):
        self.parent.deiconify()
        self.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the app?"):
            self.parent.parent.parent.end_msg("closed", self.parent.parent.parent.client_socket)
            self.parent.parent.parent.running = False
            self.destroy()