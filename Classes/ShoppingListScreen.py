import tkinter
from tkinter import *
from tkinter import messagebox

class ShoppingListScreen(tkinter.Toplevel):
    def __init__(self, parent,username,arr):
        super().__init__(parent)
        self.parent = parent

        self.geometry('600x770')
        self.title('Shopping List Screen')
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
            Label(self, textvariable=self.str,background="#B5D5C5", foreground="red", font=("Calibri", 15)).place(x=50, y=130)
        else:
            new_arr = []
            for item in arr:
                new_arr.append(item.split('^'))
            # print(new_arr)
            self.arr_favorites = new_arr
            self.create_gui()
            self.create_shopping_list()


    def create_gui(self):
        self.head_frame = Frame(self, bg="#658864", highlightbackground="white", highlightthickness=1)
        self.head_frame.pack(side=TOP, fill=X)
        self.head_frame.pack_propagate(False)
        self.head_frame.configure(height=70)
        self.title_lb = Label(self.head_frame, text="Shopping List", bg="#658864", fg="white", font=('Calibri', 20))
        self.title_lb.place(x=220, y=12)
        # _____________________________________________________________________________________________________
        self.clear_btn = Button(self, text="Clear chosen products", bd=0, background="#658864", foreground="white",
                                font=("Calibri", 15), activebackground="#658864",
                                activeforeground="white",
                                command=lambda: self.clear_shopping_list(self.list,self.username, self.parent.parent.parent.client_socket))
        self.clear_btn.place(x=370, y=90)
        # _____________________________________________________________________________________________________
        self.buy_lbl=Label(self,text="To buy:",bg="#B5D5C5",font=("Calibri",15,"underline"))
        self.buy_lbl.place(x=50,y=120)
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
            ingredient_btn.config(command=lambda current=ingredient_btn,ingredient=self.ingredient_name: (self.change_font(current), self.add_to_overstrike(ingredient)))
            ingredient_btn.place(x=50, y=Y)
            count = count + 1
            Y = Y + 25

    def change_font(self, current):
        current.config(font=("Calibri", 13, 'overstrike'))

    def add_to_overstrike(self,ingredient):
        print("List: "+ str(self.list))
        if ingredient not in self.list:
            print(ingredient)
            self.list.append(ingredient)
            return True #ingredient is not exist in the list
        else:
            return False #ingredient is exist in the list

    def clear_shopping_list(self, arr_to_delete, username, client_socket):
        arr = ["clear_shopping_list", str(arr_to_delete), username]
        print(arr)
        str_clear = "*".join(arr)
        client_socket.send(str_clear.encode())
        data = client_socket.recv(1024).decode()
        print(data)
        if data == "Shopping list cleared successfully":
            messagebox.showinfo("Success", "Shopping list cleared successfully.\nReset the window")
        elif data == "Clearing shopping list failed":
            messagebox.showerror("Fail", "Try again")


    def return_back(self):
        self.parent.deiconify()
        self.destroy()