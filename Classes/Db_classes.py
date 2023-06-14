import sqlite3
import hashlib
class RecipesDb(object):
    def __init__(self, tablename="RecipesDb",recipe_id="recipe_id", recipe_name="recipe_name",recipe_image_path="recipe_image_path",
                 category_id="category_id", nutritions="nutritions", cooking_time="cooking_time", description="description"):
        self.__tablename=tablename
        self.__recipe_id=recipe_id
        self.__recipe_name=recipe_name
        self.__recipe_image_path=recipe_image_path
        self.__category_id=category_id
        self.__nutritions=nutritions
        self.__cooking_time=cooking_time
        self.__description=description

        conn=sqlite3.connect('project_recipes.db')
        #print("Database opened successfuly")
        str= "Create table if not exists " + self.__tablename + "(" + self.__recipe_id + " " + "integer primary key autoincrement ,"
        str += " " + self.__recipe_name + " text not null ,"
        str += " " + self.__recipe_image_path + " text not null ,"
        str += " " + self.__category_id + " integer not null ,"
        str += " " + self.__nutritions + " text not null ,"
        str += " " + self.__cooking_time + " text not null ,"
        str += " " + self.__description + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה שמכניסה את פרטי המתכון לטבלה
    def insert_recipe(self, recipe_name,recipe_image_path,category_id, nutritions, cooking_time, description):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_insert = "Insert into " + self.__tablename + " (" + self.__recipe_name + "," +self.__recipe_image_path+"," +self.__category_id + "," + self.__nutritions + "," + self.__cooking_time + "," + self.__description + ") values (" + "'" + recipe_name + "'" + "," + "'" +recipe_image_path+"'" + "," + "'"+ str(
            category_id) + "'" + "," + "'" + nutritions + "'" + "," + "'" + cooking_time + "'" + "," + "'" + description + "');"
            print(str_insert)
            conn.execute(str_insert)
            conn.commit()
            conn.close()
            print("Record created successfully")
            return True
        except Exception as e:
            print("Failed to insert recipe:", e)
            return False

    # פונקציה מחזירה את פרטי המתכון
    def get_one_recipe(self,recipe_name):
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_one_recipe = "Select * from " + self.__tablename + " where " + self.__recipe_name + "=" + "'" + str(recipe_name) + "'"
            cursor = conn.execute(str_get_one_recipe)
            rows = cursor.fetchall()
            print(len(rows))
            for row in rows:
                info = str(row[0])+"*"+ row[1] +"*"+ row[2]+ "*"+ row[4] +"*"+ row[5] +"*"+ row[6]
                arr = info.split("*")
                print(arr)
            conn.close()
            if len(rows) == 0:
                info = "Not found"
            return arr
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה שם ומיקום התמונה של הקטגוריה
    def get_name_and_image_by_ctg_id(self,category_id):
        info= ""
        arr = []
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_recipe_name_image = "Select recipe_name, recipe_image_path from " + self.__tablename + " where " + self.__category_id + "=" + "'" + str(
                category_id) + "'"
            cursor = conn.execute(str_get_recipe_name_image)
            rows = cursor.fetchall()
            for row in rows:
                info += row[0] + "^" + row[1] + "#"
                arr = info.split("#")
                # print(arr)
            conn.close()
            if len(rows) == 0:
                info = "Not found"
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except:
            return "Trouble in DataBase"

    #פונקציה מוחקת מתכון מהטבלה
    def delete_recipe(self, recipe_id):
        conn = sqlite3.connect('project_recipes.db')
        str_delete_recipe = "Delete from " + self.__tablename + "where " + self.__recipe_id + "=" + "'" + str(recipe_id) + "'"
        print(str_delete_recipe)
        conn.execute(str_delete_recipe)
        conn.commit()
        conn.close()
        print("Recipe deleted successfully")

    #פונקציה בוקדת אם מתכון נמצא בטבלה
    def check_recipe(self, recipe_id):
        conn1 = sqlite3.connect('project_recipes.db')
        str_if_exist = "Select * from " + self.__tablename + " where " + self.__recipe_id + " = " + "'" + str(recipe_id) + "'"
        print(str_if_exist)
        cursor = conn1.execute(str_if_exist)
        row = cursor.fetchall()
        if row:
            print("Recipe already exists in table")
            return True
        else:
            print("Recipe not exists in table")
            return False

    #פונקציה מחזירה זמן ההכנה של המתכון
    def get_cooking_time(self,recipe_name):
        info= ""
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_cooking_time="Select cooking_time from " +self.__tablename+" where "+ self.__recipe_name + "=" + "'" + recipe_name + "'"
            cursor = conn.execute(str_get_cooking_time)
            rows = cursor.fetchall()
            #print(len(rows))
            for row in rows:
                info = "Cooking time: " + str(row[0])
                #print(row[0])
            conn.close()
            if len(rows) == 0:
                info = "Recipe is not found in the table"
            return info
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה שמות של כל המתכונים
    def get_recipe_names(self):
        info=""
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            c = conn.cursor()
            c.execute("SELECT recipe_name FROM RecipesDb")
            names = c.fetchall()
            for name in names:
                info+=name[0]+"*"
                arr = info.split("*")
            conn.close()
            if len(names) == 0:
                info = "No recipes in the table"
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה כמות המתכונים בקטגוריה מסוימת
    def get_count_recipes_same_ctg(self,category_id):
        conn = sqlite3.connect('project_recipes.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM RecipesDb WHERE category_id = ?", (category_id,))
        count = c.fetchone()[0]
        conn.close()
        return count

class CategoryDb(object):
    def __init__(self, tablename="CategoryDb", category_id="category_id",category_name="category_name",number_of_recipes="number_of_recipes", category_image="category_image"):
        self.__tablename=tablename
        self.__category_id=category_id
        self.__category_name=category_name
        self.__number_of_recipes=number_of_recipes
        self.__category_image=category_image

        conn = sqlite3.connect('project_recipes.db')
        #print("Database opened successfully")
        str = "Create table if not exists " + self.__tablename + "(" + self.__category_id + " "+ "integer primary key autoincrement ,"
        str+=" " + self.__category_name + " text not null ,"
        str+=" " + self.__number_of_recipes + " integer not null ,"
        str+=" " + self.__category_image + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה מכניסה את פרטי הקטגוריה לטבלה
    def insert_category(self, category_name, number_of_recipes, category_image):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_insert = "Insert into " + self.__tablename + " (" + self.__category_name + "," + self.__number_of_recipes+","+ self.__category_image + ") values (" + "'" + category_name + "'" + "," + "'" + str(number_of_recipes) + "'" + "," + "'" + category_image + "');"
            print(str_insert)
            conn.execute(str_insert)
            conn.commit()
            conn.close()
            print("Record created successfully")
            return True
        except:
            print("Failed to insert category")
            return False

    # פונקציה מחזירה את פרטי הקטגוריה
    def get_one_category(self,category_id):
        info = ""
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_one_category = "Select * from " + self.__tablename + " where " + self.__category_id + "=" + "'" + str(category_id) + "'"
            cursor = conn.execute(str_get_one_category)
            rows = cursor.fetchall()
            print(len(rows))
            for row in rows:
                info = "Category Id: " + str(row[0]) + "  Category Name: " + row[1] + "  Number of recipes: " + str(row[2])+" Category image path: "+row[3]
                # print(row[0], row[1], row[2],row[3])
            conn.close()
            if len(rows) == 0:
                info = "Category is not found in the table"
            return info
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה את כמות המתכונים השייכים לקטגוריה
    def get_num_of_recipes(self,category_name):
        info= ""
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_num_of_recipes="Select number_of_recipes from " +self.__tablename+" where "+ self.__category_name + "=" + "'" + category_name + "'"
            cursor = conn.execute(str_get_num_of_recipes)
            rows = cursor.fetchall()
            #print(len(rows))
            for row in rows:
                info = str(row[0])
                #print(row[0])
            conn.close()
            if len(rows) == 0:
                info = "Category is not found in the table"
            return info
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה את מיקום התמונה של הקטגוריה
    def get_image_path(self,category_name):
        info= ""
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_image_path="Select category_image from " +self.__tablename+" where "+ self.__category_name + "=" + "'" + category_name + "'"
            cursor = conn.execute(str_get_image_path)
            rows = cursor.fetchall()
            for row in rows:
                info = row[0]
                #print(row[0])
            conn.close()
            if len(rows) == 0:
                info = "Category is not found in the table"
            return info
        except:
            return "Trouble in DataBase"

    #פונקציה מוחקת אתהקטגוריה מהטבלה
    def delete_category(self,category_id):
        conn = sqlite3.connect('project_recipes.db')
        str_delete_category = "Delete from " + self.__tablename + "where " + self.__category_id + "=" + "'" + str(category_id) + "'"
        print(str_delete_category)
        conn.execute(str_delete_category)
        conn.commit()
        conn.close()
        print("Category deleted successfully")

    #פונקציה מעדכנת את כמות המתכונים בקטגוריה
    def update_number_of_recipes(self,category_id,number_of_recipes):
        conn = sqlite3.connect('project_recipes.db')
        str_update_num_of_recipes = "Update " + self.__tablename + "set " + self.__number_of_recipes + "=" + "'" + str(number_of_recipes) + "'"
        str_update_num_of_recipes += " where " + self.__category_id + "=" + "'" + str(category_id) + "'"
        print(str_update_num_of_recipes)
        conn.execute(str_update_num_of_recipes)
        conn.commit()
        conn.close()
        print("Number of recipes updated successfully")


class UsersDb(object):
    def __init__(self, tablename="UsersDb",user_id="user_id", user_email="user_email", user_name="user_name", password="password"):
        self.__tablename=tablename
        self.__user_id=user_id
        self.__user_email=user_email
        self.__user_name=user_name
        self.__password=password

        conn=sqlite3.connect('project_recipes.db')
        #print("Database opened successfully")
        str= "Create table if not exists " + self.__tablename + "(" + self.__user_id + " "+ "integer primary key autoincrement ,"
        str+= " " + self.__user_email + " text not null ,"
        str+= " " + self.__user_name + " text not null ,"
        str+= " " + self.__password + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה מכניסה את פרטי המשתמש לטבלה
    def insert_user(self, user_email, user_name, password):
        try:
            conn = sqlite3.connect('project_recipes.db')
            if self.check_user(user_name,password)=="Fail":
                salt = "ARINA"
                md5hash = hashlib.md5(salt.encode('utf-8') + password.encode()).hexdigest()
                str_insert = "Insert into " + self.__tablename + " (" + self.__user_email + "," + self.__user_name + "," + self.__password + ") values (" + "'" + user_email + "'" + "," + "'" + user_name + "'" + "," + "'" + str(md5hash) + "');"
                print(str_insert)
                conn.execute(str_insert)
                conn.commit()
                conn.close()
            else:
                print("Already exists")
                return "Exists"
            print("Record created successfully")
            return True
        except:
            print("Failed to insert user")
            return False


    # פונקציה מחזירה את פרטי המשתמש
    def get_one_user(self, user_name):
        info = ""
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_one_user = "Select * from " + self.__tablename + " where " + self.__user_name + "=" + "'" + str(
                user_name) + "'"
            cursor = conn.execute(str_get_one_user)
            rows = cursor.fetchall()
            print(len(rows))
            for row in rows:
                info = "User Id: " + str(row[0]) + "  User Email: " + row[1] + "  User Name: " + row[2] + "  Password: "+ row[3]
                print(row[0], row[1], row[2],row[3])
            conn.close()
            if len(rows) == 0:
                info = "User is not found in the table"
            return info
        except:
            return "Trouble in DataBase"


    # פונקציה מחזירה פרטים של כל המשתמשים
    def get_all_users(self,username):
        info=""
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_all_users = "Select * from "+ self.__tablename+" where "+self.__user_name+"!="+"'"+username+"'"
            cursor = conn.execute(str_get_all_users)
            rows = cursor.fetchall()
            for row in rows:
                info+=row[2]+"*"
                arr = info.split("*")
            print(info)
            conn.close()
            if len(rows) == 0:
                if len(arr) == 0:
                    arr.append("No users")
                else:
                    arr[0] = "No users"
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except sqlite3.Error as e:
            print("Error while connecting to database:", e)
            return "Trouble in DataBase"


    # פונקציה מחזירה את פרטי האימייל של המשתמש
    def get_email_by_name(self,username):
        info = ""
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_email = "Select user_email from " + self.__tablename + " where " + self.__user_name + "=" + "'" + username + "'"
            cursor = conn.execute(str_get_email)
            rows = cursor.fetchall()
            # print(len(rows))
            for row in rows:
                info = str(row[0])
                #print(info)
            conn.close()
            if len(rows) == 0:
                info = "Category is not found in the table"
            return info
        except:
            return "Trouble in DataBase"


    # פונקציהבודקת אם המשתמש קיים בטבלה
    def check_user(self, user_name, password):
        conn = sqlite3.connect('project_recipes.db')
        salt = "ARINA"
        md5hash = hashlib.md5(salt.encode('utf-8') + password.encode()).hexdigest()
        str_is_exist = "SELECT * from " + self.__tablename + " where " + self.__user_name + " = ?"
        cursor = conn.execute(str_is_exist, (user_name,))
        row = cursor.fetchone()
        if row:
            stored_password = row[3]
            if row[2] == user_name and stored_password == md5hash:
                print("User is exist in table")
                return True
            elif row[2] == user_name and stored_password != md5hash:
                print("Wrong password")
                return False
        else:
            print("User is not exist in table")
            return "Fail"

    # פונקציה מעדכנת את כתובת המייל של המשתמש
    def update_email(self,username,user_email):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_update_email = "Update " + self.__tablename + " set " + self.__user_email + "=" + "'" + user_email + "'"
            str_update_email += " where " + self.__user_name + "=" + "'" + str(username) + "'"
            # print(str_update_email)
            conn.execute(str_update_email)
            conn.commit()
            conn.close()
            print("Email updated successfully")
            return True
        except:
            print("Failed to change email")
            return False

    # פונקציה מעדכנת את הסיסמא של המשתמש
    def update_password(self,username,user_password):
        try:
            if self.check_user(username, user_password) == True:
                conn = sqlite3.connect('project_recipes.db')
                salt = "ARINA"
                md5hash = hashlib.md5(salt.encode('utf-8') + user_password.encode()).hexdigest()
                str_update_password = "Update " + self.__tablename + " set " + self.__password + "=" + "'" + str(md5hash) + "'"
                str_update_password += " where " + self.__user_name + "=" + "'" + str(username) + "'"
                print(str_update_password)
                conn.execute(str_update_password)
                conn.commit()
                conn.close()
                print("Password updated successfully")
                return True
            elif self.check_user(username, user_password) == "Fail":
                return "Fail,user doesn't exist"
        except:
            print("Failed to change password")
            return False

    # פונקציה מוחקת את פרטי המשתמש מהטבלה
    def delete_user(self,username):
        conn = sqlite3.connect('project_recipes.db')
        str_delete_user = "Delete from " + self.__tablename + " where " + self.__user_name + "=" + "'" + username + "'"
        print(str_delete_user)
        conn.execute(str_delete_user)
        conn.commit()
        conn.close()
        print("User deleted successfully")

class IngredientsDb(object):
    def __init__(self, tablename="IngredientsDb",ingredient_id="ingredient_id",ingredient_name="ingredient_name",ingredient_amount="ingredient_amount",recipe_name="recipe_name"):
        self.__tablename=tablename
        self.__ingredient_id=ingredient_id
        self.__ingredient_name=ingredient_name
        self.__ingredient_amount=ingredient_amount
        self.__recipe_name = recipe_name

        conn=sqlite3.connect('project_recipes.db')
        str = "Create table if not exists " + self.__tablename + "(" + self.__ingredient_id + " " + "integer primary key autoincrement ,"
        str += " " + self.__ingredient_name + " text not null ,"
        str += " " + self.__ingredient_amount + " text not null ,"
        str += " " + self.__recipe_name + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה מכניסה את פרטי המצרך לטבלה
    def insert_ingredient(self, ingredient_name, ingredient_amount, recipe_name):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_insert = "Insert into " + self.__tablename + " (" + self.__ingredient_name + "," + self.__ingredient_amount + ","+ self.__recipe_name + ") values (" + "'" + ingredient_name + "'" + "," + "'" + ingredient_amount + "'" + "," + "'" + recipe_name +"');"
            print(str_insert)
            conn.execute(str_insert)
            conn.commit()
            conn.close()
            print("Record created successfully")
            return True
        except:
            print("Failed to insert ingredient")
            return False

    # פונקציה מחזירה את פרטי המצרך
    def get_one_ingredient(self, ingredient_id):
        info = ""
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_one_ingredient = "Select * from " + self.__tablename + " where " + self.__ingredient_id + "=" + "'" + str(
                ingredient_id) + "'"
            cursor = conn.execute(str_get_one_ingredient)
            rows = cursor.fetchall()
            print(len(rows))
            for row in rows:
                info = "Ingredient id: " + str(row[0]) + "  Ingredient Name: " + row[1] + "  Ingredient Amount: " + str(
                    row[2]) + "Recipe name: " + row[3]
                print(row[0], row[1], row[2],row[3])
            conn.close()
            if len(rows) == 0:
                info = "Not found"
            return info
        except:
            return "Trouble on db"

    # פונקציה מחזירה את המצרכים של המתכון מסוים
    def get_ingredients_by_recipe_name(self,recipe_name):
        info = ""
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_ingredients_same_recipe = "Select * from " + self.__tablename + " where " + self.__recipe_name + "=" + "'" + recipe_name + "'"
            cursor = conn.execute(str_get_ingredients_same_recipe)
            rows = cursor.fetchall()
            # print(len(rows))
            for row in rows:
                info += row[1] + "(" + str(row[2]) + ")" + "\n"
                # print(row[1], row[2])
                arr=info.split("\n")
            # print(arr)
            conn.close()
            if len(rows) == 0:
                arr[0] = "No ingredients"
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except:
            return "Trouble on db"

    # פונקציה מחזירה פרטים של כל המתכונים
    def get_all_ingredients(self):
        conn = sqlite3.connect('project_recipes.db')
        str_get_all_ingredients = "Select * from "+ self.__tablename
        cursor = conn.execute(str_get_all_ingredients)
        for row in cursor:
            print("Ingredient_id=", row[0])
            print("Ingredient_name=", row[1])
            print("Ingredient_amount=", row[2])
            print("Recipe_id",row[3])
            print("_____________________________________")
        print("Success")
        conn.close()

    # פונקציה מחזירה את פרטי המצרך עם שם המתכון
    def get_one_ingredient_with_recipe_name(self):
        conn = sqlite3.connect('project_recipes.db')
        str = ("""
                SELECT ingredient_id, ingredient_name, ingredient_amount, RecipesDb.recipe_name
                FROM RecipesDb
                INNER JOIN IngredientsDb ON IngredientsDb.recipe_id = RecipesDb.recipe_id
                """)
        cursor = conn.execute(str)
        for row in cursor:
            print("ingredient_id =", row[0])
            print("ingredient_name =", row[1])
            print("ingredient_amount =", row[2])
            print("recipe_name =", row[3])
        conn.commit()
        conn.close()

    # פונקציה בודקת אם המצרך קיים בטבלה
    def check_ingredient(self,ingredient_id):
        conn1 = sqlite3.connect('project_recipes.db')
        str_if_exist = "Select * from " + self.__tablename + " where " + self.__ingredient_id + " = " + "'" + str(
            ingredient_id) + "'"
        # print(str_if_exist)
        cursor = conn1.execute(str_if_exist)
        row = cursor.fetchall()
        if row:
            print("Ingredient already exists in table")
            return True
        else:
            print("Ingredient not exists in table")
            return False

    #פונקציה מוחקת את המצרך מהטבלה
    def delete_ingredient(self,ingredient_id):
        conn = sqlite3.connect('project_recipes.db')
        str_delete_ingredient = "Delete from " + self.__tablename + " where " + self.__ingredient_id + "=" + "'" + str(
            ingredient_id) + "'"
        print(str_delete_ingredient)
        conn.execute(str_delete_ingredient)
        conn.commit()
        conn.close()
        print("Ingredient deleted successfully")


class HistoryRecipesDb(object):
    def __init__(self, tablename="HistoryRecipesDb",recipe_id="recipe_id", recipe_name="recipe_name",recipe_image_path="recipe_image_path", nutritions="nutritions", cooking_time="cooking_time", description="description",username="username"):
        self.__tablename=tablename
        self.__recipe_id=recipe_id
        self.__recipe_name=recipe_name
        self.__recipe_image_path = recipe_image_path
        self.__nutritions = nutritions
        self.__cooking_time = cooking_time
        self.__description = description
        self.__username = username

        conn=sqlite3.connect('project_recipes.db')
        #print("Database opened successfuly")
        str= "Create table if not exists " + self.__tablename + "(" + self.__recipe_id + " " + "integer primary key autoincrement ,"
        str += " " + self.__recipe_name + " text not null ,"
        str += " " + self.__recipe_image_path + " text not null ,"
        str += " " + self.__nutritions + " text not null ,"
        str += " " + self.__cooking_time + " text not null ,"
        str += " " + self.__description + " text not null ,"
        str += " " + self.__username + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה שמכניסה את פרטי המתכון לטבלה
    def insert_recipe(self, recipe_name, recipe_image_path, nutritions, cooking_time, description, username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            if self.check_recipe(recipe_name,username)==False:
                str_insert = "Insert into " + self.__tablename + " (" + self.__recipe_name + "," + self.__recipe_image_path + "," + self.__nutritions + "," + self.__cooking_time + "," + self.__description + "," + self.__username + ") values (" + "'" + recipe_name + "'" + "," + "'" + recipe_image_path + "'" + "," + "'" + nutritions + "'" + "," + "'" + cooking_time + "'" + "," + "'" + description+"'" + "," + "'"+username + "');"
                print(str_insert)
                conn.execute(str_insert)
                conn.commit()
                conn.close()
            else:
                print("Already exists")
                return False
            # print(str_insert)
            print("Record created successfully")
            return True
        except Exception as e:
            print("Failed to insert recipe:", e)
            return False

    # פונקציה מחזירה את פרטי המתכון
    def get_one_recipe(self,recipe_name):
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_one_recipe = "Select * from " + self.__tablename + " where " + self.__recipe_name + "=" + "'" + str(recipe_name) + "'"
            cursor = conn.execute(str_get_one_recipe)
            rows = cursor.fetchall()
            print(len(rows))
            for row in rows:
                info = str(row[0])+"*"+ row[1]
                arr = info.split("*")
                print(arr)
            conn.close()
            if len(rows) == 0:
                info = "Not found"
            return arr
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה את כל המתכונים השייכים למשתמש מסוים
    def get_all_recipes(self,username):
        info=""
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_all_recipes = "Select * from "+ self.__tablename + " where "+ self.__username + "="+ "'"+ username + "'"
            print(str_get_all_recipes)
            cursor = conn.execute(str_get_all_recipes)
            rows = cursor.fetchall()

            for row in rows:
                info += str(row[0])+"^"+row[1]+"^"+row[2]+"^"+row[3]+"^"+row[4]+"^"+row[5]+"#"
                arr = info.split("#")
            conn.close()
            if len(rows) == 0:
                return 0
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except:
            return "Trouble on db"

    #פונקציה מוחקת את כל המתכונים השייכים למשתמש מסוים
    def delete_all_recipes(self,username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_delete_recipe = "DELETE FROM " + self.__tablename + " where "+ self.__username + "="+ "'"+ username + "'"
            print(str_delete_recipe)
            cursor = conn.execute(str_delete_recipe)
            # Reset the recipe_id sequence
            # str_reset_sequence = "UPDATE sqlite_sequence SET seq=0 WHERE name='" + self.__tablename + "'"
            # conn.execute(str_reset_sequence)
            conn.commit()
            conn.close()
            if cursor.rowcount > 0:
                print("Recipes deleted successfully")
                return True
            else:
                print("Deleting recipes failed")
                conn.close()
                return False
        except:
            return "Trouble on db"

    #פונקציה בודקת את המתכון השייך למשתמש מסוים קיים בטבלה
    def check_recipe(self, recipe_name, username):
        conn1 = sqlite3.connect('project_recipes.db')
        str_if_exist = "Select * from " + self.__tablename + " where " + self.__recipe_name + " = " + "'" + recipe_name + "' and " + self.__username + " = " + "'" + username + "'"
        # print(str_if_exist)
        cursor = conn1.execute(str_if_exist)
        row = cursor.fetchall()
        if row:
            # print("Recipe already exists in table")
            return True
        else:
            # print("Recipe not exists in table")
            return False

    #פונקציה מוחקת את המתכונים בקיבלה במערך ששייכים למשתמש מסוים
    def delete_few_recipes(self, username, arr):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_delete_recipe = "DELETE FROM " + self.__tablename + " WHERE " + self.__username + " = ? AND recipe_name = ?"

            recipes_deleted = 0

            for recipe_name in arr:
                cursor = conn.execute(str_delete_recipe, (username, recipe_name))
                if cursor.rowcount > 0:
                    recipes_deleted += 1

            conn.commit()
            conn.close()

            if recipes_deleted > 0:
                print("Recipes deleted successfully")
                return True
            else:
                print("Recipes deleted successfully")
                return False
        except:
            return "Trouble on db"


class FavoritesRecipesDb(object):
    def __init__(self, tablename="FavoritesRecipesDb",recipe_id="recipe_id", recipe_name="recipe_name",recipe_image_path="recipe_image_path", nutritions="nutritions", cooking_time="cooking_time", description="description",username="username"):
        self.__tablename=tablename
        self.__recipe_id=recipe_id
        self.__recipe_name=recipe_name
        self.__recipe_image_path = recipe_image_path
        self.__nutritions = nutritions
        self.__cooking_time = cooking_time
        self.__description = description
        self.__username = username

        conn=sqlite3.connect('project_recipes.db')
        #print("Database opened successfuly")
        str= "Create table if not exists " + self.__tablename + "(" + self.__recipe_id + " " + "integer primary key autoincrement ,"
        str += " " + self.__recipe_name + " text not null ,"
        str += " " + self.__recipe_image_path + " text not null ,"
        str += " " + self.__nutritions + " text not null ,"
        str += " " + self.__cooking_time + " text not null ,"
        str += " " + self.__description + " text not null ,"
        str += " " + self.__username + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה שמכניסה את פרטי המתכון לטבלה
    def insert_recipe(self, recipe_name, recipe_image_path, nutritions, cooking_time, description, username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            if self.check_recipe(recipe_name,username)==False:
                str_insert = "Insert into " + self.__tablename + " (" + self.__recipe_name + "," + self.__recipe_image_path + "," + self.__nutritions + "," + self.__cooking_time + "," + self.__description + "," + self.__username + ") values (" + "'" + recipe_name + "'" + "," + "'" + recipe_image_path + "'" + "," + "'" + nutritions + "'" + "," + "'" + cooking_time + "'" + "," + "'" + description+"'" + "," + "'"+ username + "');"
                print(str_insert)
                conn.execute(str_insert)
                conn.commit()
                conn.close()
            else:
                print("Already exists")
                return False
            # print(str_insert)
            print("Record created successfully")
            return True
        except Exception as e:
            print("Failed to insert recipe:", e)
            return False

    # פונקציה מחזירה את פרטי המתכון
    def get_one_recipe(self,recipe_name):
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_one_recipe = "Select * from " + self.__tablename + " where " + self.__recipe_name + "=" + "'" + recipe_name + "'"
            cursor = conn.execute(str_get_one_recipe)
            rows = cursor.fetchall()
            print(len(rows))
            for row in rows:
                info = str(row[0])+"*"+ row[1]
                arr = info.split("*")
                print(arr)
            conn.close()
            if len(rows) == 0:
                info = "Not found"
            return arr
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה את כל המתכונים
    def get_all_recipes(self,username):
        info=""
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_all_recipes = "Select * from "+ self.__tablename + " where "+ self.__username + "="+ "'"+ username + "'"
            # print(str_get_all_recipes)
            cursor = conn.execute(str_get_all_recipes)
            rows = cursor.fetchall()

            for row in rows:
                info += str(row[0])+"^"+row[1]+"^"+row[2]+"^"+row[3]+"^"+row[4]+"^"+row[5]+"#"
                arr = info.split("#")
            conn.close()
            if len(rows) == 0:
                return 0
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except:
            return "Trouble on db"

    #פונקציה מוחקת את כל המתכונים השייכים למשתמש מסוים
    def delete_all_recipes(self,username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_delete_recipe = "DELETE FROM " + self.__tablename + " where "+ self.__username + "="+ "'"+ username + "'"
            print(str_delete_recipe)
            cursor = conn.execute(str_delete_recipe)
            conn.commit()
            conn.close()
            if cursor.rowcount > 0:
                print("Recipes deleted successfully")
                return True
            else:
                print("Deleting recipes failed")
                conn.close()
                return False
        except:
            return "Trouble on db"

    #פונקציה בודקת את המתכון השייך למשתמש מסוים קיים בטבלה
    def check_recipe(self, recipe_name, username):
        conn1 = sqlite3.connect('project_recipes.db')
        str_if_exist = "Select * from " + self.__tablename + " where " + self.__recipe_name + " = " + "'" + recipe_name + "' and "+self.__username + " = "+ "'" + username+ "'"
        # print(str_if_exist)
        cursor = conn1.execute(str_if_exist)
        row = cursor.fetchall()
        if row:
            print("Recipe already exists in table")
            return True
        else:
            print("Recipe not exists in table")
            return False

class SendReceiveRecipesDb(object):
    def __init__(self, tablename="SendReceiveRecipesDb",recipe_id="recipe_id", recipe_name="recipe_name",recipe_image_path="recipe_image_path", nutritions="nutritions", cooking_time="cooking_time", description="description",from_username="from_username",to_username="to_username"):
        self.__tablename=tablename
        self.__recipe_id=recipe_id
        self.__recipe_name=recipe_name
        self.__recipe_image_path = recipe_image_path
        self.__nutritions = nutritions
        self.__cooking_time = cooking_time
        self.__description = description
        self.__from_username = from_username
        self.__to_username = to_username

        conn=sqlite3.connect('project_recipes.db')
        #print("Database opened successfuly")
        str= "Create table if not exists " + self.__tablename + "(" + self.__recipe_id + " " + "integer primary key autoincrement ,"
        str += " " + self.__recipe_name + " text not null ,"
        str += " " + self.__recipe_image_path + " text not null ,"
        str += " " + self.__nutritions + " text not null ,"
        str += " " + self.__cooking_time + " text not null ,"
        str += " " + self.__description + " text not null ,"
        str += " " + self.__from_username + " text not null ,"
        str += " " + self.__to_username + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה שמכניסה את פרטי המתכון לטבלה
    def insert_recipe(self, recipe_name, recipe_image_path, nutritions, cooking_time, description, from_username,to_username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            if self.check_recipe(recipe_name,from_username,to_username)==False:
                str_insert = "Insert into " + self.__tablename + " (" + self.__recipe_name + "," + self.__recipe_image_path + "," + self.__nutritions + "," + self.__cooking_time + "," + self.__description + "," + self.__from_username+","+self.__to_username+ ") values (" + "'" + recipe_name + "'" + "," + "'" + recipe_image_path + "'" + "," + "'" + nutritions + "'" + "," + "'" + cooking_time + "'" + "," + "'" + description + "'" + "," + "'" + from_username + "'" + "," + "'"+ to_username + "');"
                print(str_insert)
                conn.execute(str_insert)
                conn.commit()
                conn.close()
            else:
                print("Already exists")
                return False
            # print(str_insert)
            print("Record created successfully")
            return True
        except Exception as e:
            print("Failed to insert recipe:", e)
            return False

    # פונקציה מחזירה את פרטי המתכון
    def get_one_recipe(self,recipe_name):
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_one_recipe = "Select * from " + self.__tablename + " where " + self.__recipe_name + "=" + "'" + str(recipe_name) + "'"
            cursor = conn.execute(str_get_one_recipe)
            rows = cursor.fetchall()
            print(len(rows))
            for row in rows:
                info = str(row[0])+"*"+ row[1]
                arr = info.split("*")
                print(arr)
            conn.close()
            if len(rows) == 0:
                info = "Not found"
            return arr
        except:
            return "Trouble in DataBase"

    #פונקציה מחזירה את כל המתכונים השייכים למשתמש מסוים
    def get_all_recipes(self,to_username):
        info=""
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_all_recipes = "Select * from "+ self.__tablename + " where "+ self.__to_username + "="+ "'"+ to_username + "'"
            # print(str_get_all_recipes)
            cursor = conn.execute(str_get_all_recipes)
            rows = cursor.fetchall()
            for row in rows:
                info += str(row[0])+"^"+row[1]+"^"+row[2]+"^"+row[3]+"^"+row[4]+"^"+row[5]+"^"+row[6]+"#"
                arr = info.split("#")
            conn.close()
            if len(rows) == 0:
                return 0
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except:
            return "Trouble on db"

    #פונקציה מוחקת את כל המתכונים השייכים למשתמש מסוים
    def delete_all_recipes(self,to_username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_delete_recipe = "DELETE FROM " + self.__tablename + " where "+ self.__to_username + "="+ "'"+ to_username + "'"
            print(str_delete_recipe)
            cursor = conn.execute(str_delete_recipe)
            conn.commit()
            conn.close()
            if cursor.rowcount > 0:
                print("Recipes deleted successfully")
                return True
            else:
                print("Deleting recipes failed")
                conn.close()
                return False
        except:
            return "Trouble on db"

    #פונקציה בודקת את המתכון השייך למשתמש מסוים קיים בטבלה
    def check_recipe(self, recipe_name,from_username, to_username):
        conn1 = sqlite3.connect('project_recipes.db')
        str_if_exist = "Select * from " + self.__tablename + " where " + self.__recipe_name + " = " + "'" + recipe_name + "' and "+self.__from_username + " = "+ "'" + from_username +"' and "+self.__to_username + " = "+ "'" + to_username+ "'"
        print(str_if_exist)
        cursor = conn1.execute(str_if_exist)
        row = cursor.fetchall()
        if row:
            print("Recipe already exists in table")
            return True
        else:
            print("Recipe not exists in table")
            return False


class ShoppingListDb(object):
    def __init__(self, tablename="ShoppingListDb",ingredient_id="ingredient_id",ingredient_name="ingredient_name",username="username"):
        self.__tablename=tablename
        self.__ingredient_id=ingredient_id
        self.__ingredient_name=ingredient_name
        self.__username=username

        conn=sqlite3.connect('project_recipes.db')
        str = "Create table if not exists " + self.__tablename + "(" + self.__ingredient_id + " " + "integer primary key autoincrement ,"
        str += " " + self.__ingredient_name + " text not null ,"
        str += " " + self.__username + " text not null )"
        conn.execute(str)
        # print("Table created successfully")
        conn.commit()
        conn.close()

    #פונקציה מכניסה את פרטי המצרך לטבלה
    def insert_ingredient(self, ingredient_name, username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            if self.check_ingredient(ingredient_name,username)==False:
                str_insert = "Insert into " + self.__tablename + " (" + self.__ingredient_name + "," + self.__username + ") values (" + "'" + ingredient_name + "'" + "," + "'" + username +"');"
                print(str_insert)
                conn.execute(str_insert)
                conn.commit()
                conn.close()
                print("Record created successfully")
                return True
            else:
                print("Already exists")
                return False
        except:
            print("Failed to insert ingredient")
            return False

    #פונקציה מחזירה מצרכים השייכים למשתמש מסוים
    def get_ingredients_by_username(self,username):
        info = ""
        arr=[]
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_get_ingredients = "Select * from " + self.__tablename + " where " + self.__username + "=" + "'" + username + "'"
            # print(str_get_ingredients)
            cursor = conn.execute(str_get_ingredients)
            rows = cursor.fetchall()
            # print(len(rows))
            for row in rows:
                info += row[1]+"\n"
                arr=info.split("\n")
            # print(arr)
            conn.close()
            if len(rows) == 0:
                return 0
            if arr and arr[-1] == "":
                arr.pop()
            return arr
        except:
            return "Trouble on db"

    # פונקציה בודקת אם המצרך קיים בטבלה
    def check_ingredient(self,ingredient_name,username):
        conn1 = sqlite3.connect('project_recipes.db')
        str_if_exist = "SELECT * FROM " + self.__tablename + " WHERE " + self.__ingredient_name + " = '" + ingredient_name + "' AND " + self.__username + " = '" + username + "'"
        print(str_if_exist)
        cursor = conn1.execute(str_if_exist)
        row = cursor.fetchall()
        if row:
            print("Ingredient already exists in table")
            return True
        else:
            print("Ingredient not exists in table")
            return False

    #פונקציה מוחקת את המצרכים מהטבלה לפי פרטי המשתמש אליו הם שייכים
    def delete_ingredients_by_name_and_username(self, arr, username):
        try:
            conn = sqlite3.connect('project_recipes.db')
            str_delete_ingredients = f"DELETE FROM {self.__tablename} WHERE {self.__username}=? AND {self.__ingredient_name} IN ({','.join(['?'] * len(arr))})"
            cursor = conn.execute(str_delete_ingredients, [username] + arr)
            conn.commit()
            conn.close()
            if cursor.rowcount > 0:
                print("Ingredients deleted successfully")
                return True
            else:
                print("No matching ingredients found")
                return False
        except:
            return "Trouble on db"


R=RecipesDb()
C=CategoryDb()
U=UsersDb()
I=IngredientsDb()
H=HistoryRecipesDb()
F=FavoritesRecipesDb()
S=ShoppingListDb()


def insert_rcp(arr):
    for name, image, id_c, nutritions, time, instruction in arr:
        R.insert_recipe(name, image, id_c, nutritions, time, instruction)

arr_recipes=[("Aussie Sausage Rolls",'photos/recipes/Aussie Sausage Rolls.jpg',1,"116 calories","40 minutes","Preheat oven to 350°.Combine first 6 ingredients and 3/4 teaspoon paprika. Add sausage; mix lightly but thoroughly. On a lightly floured surface, roll each pastry sheet into an 11x10-1/2-in. Rectangle. Cut lengthwise into 3 strips. Spread 1/2 cup sausage mixture lengthwise down the center of each strip. Fold over sides, pinching edges to seal. Cut each log into 6 pieces. Place on a rack in a 15x10x1-in. pan, seam side down. Sprinkle with remaining 1/4 teaspoon paprika. Bake until golden brown and sausage is no longer pink, 20-25 minutes."),
            ("Chicken & Bacon Roll Ups",'photos/recipes/Chicken & Bacon Roll Ups.jpg',1,"43 calories","20 minutes","Mix chicken, cream cheese, 1/2 cup salsa and bacon; spread over tortillas. Roll up tightly; wrap. Refrigerate at least 1 hour. Just before serving, unwrap and cut tortillas into 1-in. slices. Serve with remaining salsa."),
            ("Party Shrimps",'photos/recipes/Party Shrimps.jpg',1,"14 calories","25 minutes","In a bowl or shallow dish, combine the first 7 ingredients. Add shrimp; toss to coat. Refrigerate 2 hours. Drain shrimp, discarding marinade. Place shrimp on an ungreased baking sheet. Broil 4 in. from heat until shrimp turn pink, 3-4 minutes on each side."),
            ("South-of-Border Bruschetta",'photos/recipes/South-of-Border Bruschetta.jpg',1,"62 calories","25 minutes","In a small bowl, mix avocados, cilantro, chili peppers and salt. Finely grate zest from limes. Cut limes crosswise in half; squeeze juice from limes. Stir lime zest and juice into avocado mixture. Refrigerate 30 minutes. Preheat broiler. Place bread slices on an ungreased baking sheet. Broil 3-4 in. from heat 1-2 minutes on each side or until golden brown. Top with avocado mixture. If desired, sprinkle with cheese."),
            ("Asian Chicken Noodle Soup",'photos/recipes/Asian Chicken Noodle Soup.jpg',2,"227 calories","40 minutes","In a Dutch oven, cook chicken in oil over medium heat until no longer pink. Remove and keep warm. In the same pan, saute the carrots, celery and onion until tender. Stir in the broth, teriyaki sauce, garlic sauce and chicken. Bring to a boil. Reduce heat; simmer, uncovered, for 20 minutes. Add the wonton strips, mushrooms, celery leaves, basil and cilantro. Cook and stir for 4-5 minutes or until wonton strips and mushrooms are tender. Sprinkle with green onions."),
            ("Tortellini Spinach Soup",'photos/recipes/Tortellini Spinach Soup.jpg',2,"177 calories","20 minutes","Place the first 5 ingredients in a 6-qt. stockpot; bring to a boil. Reduce heat; simmer, covered, 10 minutes. Return to a boil. Add tortellini; cook, uncovered, until meatballs are heated through and tortellini are tender, 3-5 minutes, stirring occasionally. Stir in spinach until wilted. Serve immediately. If desired, top with cheese."),
            ("Cheesy Potato Soup",'photos/recipes/Cheesy Potato Soup.jpg',2,"296 calories","35 minutes","Melt butter in a Dutch oven over medium-high heat. Add onion; cook and stir until tender, 5 minutes. Add potatoes and water; bring to a boil. Reduce heat; cover and simmer until potatoes are tender, 15 minutes. Stir in the milk, soup, garlic salt and pepper; heat until warmed through. Add cheese; stir until cheese is melted. Sprinkle with parsley."),
            ("Onion Cheese Soup",'photos/recipes/Onion Cheese Soup.jpg',2,"308 calories","25 minutes","In a large saucepan, saute the onion in butter. Stir in the flour, salt and pepper until blended. Gradually add milk. Bring to a boil; cook and stir for 2 minutes or until thickened. Stir in cheese until melted. Serve with croutons and; if desired, top with Parmesan cheese and minced chives."),
            ("Breaded Pork Chops",'photos/recipes/Breaded Pork Chops.jpg',3,"405 calories","20 minutes","In a shallow bowl, combine egg and milk. Place cracker crumbs in another shallow bowl. Dip each pork chop in egg mixture, then coat with cracker crumbs, patting to make a thick coating.In a large skillet, cook chops in oil for 4-5 minutes on each side or until a thermometer reads 145°. Let meat stand for 5 minutes before serving."),
            ("Chicken with Butter Sauce",'photos/recipes/Chicken with Butter Sauce.jpg',3,"411 calories","25 minutes","In a large skillet over medium heat, cook chicken in 1 tablespoon butter until a thermometer reads 165°, 4-5 minutes on each side. Remove and keep warm. Add wine to pan; cook over medium-low heat, stirring to loosen browned bits from pan. Add cream and bring to a boil. Reduce heat; cook and stir until slightly thickened. Stir in rosemary and remaining 3 tablespoons butter until blended. Serve sauce with chicken."),
            ("Parmesan Chicken Breast",'photos/recipes/Parmesan Chicken Breast.jpg',3,"391 calories","30 minutes","Combine cheese, bread crumbs and butter. Coat chicken breasts with mustard, then dip into crumb mixture. Place breaded chicken in a 13x9-in. baking pan. Bake at 425° until a thermometer inserted in chicken reads 165°, about 15 minutes."),
            ("Ravioli Lasagna",'photos/recipes/Ravioli Lasagna.jpg',3,"438 calories","40 minutes","In a large skillet, cook and crumble beef over medium heat until no longer pink, 5-7 minutes; drain. In a greased 2-1/2-qt. baking dish, layer a third of the spaghetti sauce, half of the ravioli and beef, and 1/2 cup cheese; repeat layers. Top with remaining sauce and cheese. Cover and bake at 400° until heated through, 40-45 minutes. If desired, top with basil to serve."),
            ("Sausage Hash",'photos/recipes/Sausage Hash.jpg',3,"245 calories","30 minutes","In a large cast-iron or other heavy skillet, cook the sausage over medium heat until no longer pink; drain. Add the onion, carrots and green pepper; cook until tender. Stir in the potatoes, salt and pepper. Reduce heat; cook and stir until lightly browned and heated through, about 20 minutes."),
            ("Bacon Chopped Salad",'photos/recipes/Bacon Chopped Salad.jpg',4,"348 calories","20 minutes","Heat chicken according to package directions. Cool slightly; coarsely chop chicken. For dressing, place cheese, vinegar, water and pepper in a small food processor; cover and process until smooth. While processing, gradually add oil in a steady stream. In a large bowl, combine romaine, chicken, tomatoes and bacon. Serve with dressing."),
            ("Caesar Salad",'photos/recipes/Caesar Salad.jpg',4,"265 calories","10 minutes","Place lettuce in a large salad bowl. Combine the next 6 ingredients in a blender; process until smooth. Pour over lettuce and toss to coat. Squeeze lemon juice over lettuce. Sprinkle with pepper, cheese and croutons."),
            ("Caprese Salad",'photos/recipes/Caprese Salad.jpg',4,"256 calories","15 minutes","Arrange the tomatoes, cheese and basil on a serving platter. Whisk the vinaigrette ingredients; drizzle over salad. If desired, sprinkle with additional salt and pepper."),
            ("Garden Tomato Salad",'photos/recipes/Garden Tomato Salad.jpg',4,"92 calories","15 minutes","In a large bowl, combine tomatoes, onion and cucumber. In a small bowl, whisk dressing ingredients until blended. Drizzle over salad; gently toss to coat. Serve immediately."),
            ("Greek Salad",'photos/recipes/Greek Salad.jpg',4,"148 calories","20 minutes","Place tomatoes, cucumbers and onion in a large bowl. In a small bowl, whisk oil, vinegar, salt and pepper and, if desired, oregano until blended. Drizzle over salad; toss to coat. Top with olives and cheese."),
            ("Berry Dream Cake",'photos/recipes/Berry Dream Cake.jpg',5,"306 calories","45 minutes","Prepare and bake cake mix batter according to package directions, using a greased 13x9-in. baking pan. In a small bowl, add boiling water to gelatin; stir 2 minutes to completely dissolve. Cool cake on a wire rack 3-5 minutes. Using a wooden skewer, pierce holes in top of cake to within 1 in. of edge, twisting skewer gently to make slightly larger holes. Gradually pour gelatin over cake, being careful to fill each hole. Cool 15 minutes. Refrigerate, covered, 30 minutes. In a large bowl, beat cream cheese until fluffy. Fold in whipped topping. Carefully spread over cake. Top with strawberries. Cover and refrigerate for at least 2 hours"),
            ("Cherry Tarts",'photos/recipes/Cherry Tarts.jpg',5,"362 calories","10 minutes","In a small bowl, beat the cream cheese, sugar and extract until smooth. Spoon into shells. Top with pie filling. Refrigerate until serving."),
            ("Chocolate Molten Cakes",'photos/recipes/Chocolate Molten Cakes.jpg',5,"560 calories","30 minutes","Preheat oven to 425°. In a microwave, melt butter and chocolate; stir until smooth. Stir in wine and vanilla. In a small bowl, beat the egg, egg yolk and confectioners sugar until thick and lemon-colored. Beat in the flour, ginger and cinnamon until well blended. Gradually beat in butter mixture. Transfer to 2 greased 6-oz. ramekins or custard cups. Place ramekins on a baking sheet. Bake until a thermometer inserted in the center reads 160° and sides of cakes are set, 10-12 minutes. Remove from the oven and let stand for 1 minute. Run a knife around edges of ramekins; invert onto dessert plates. Dust with additional confectioners sugar. Serve immediately."),
            ("Citrus Cider Punch",'photos/recipes/Citrus Cider Punch.jpg',6,"138 calories","5 minutes","In a large punch bowl, combine cider and lemonade. Add lemon slices and apple rings. If desired, serve with additional lemon slices and apple rings."),
            ("Cranberry Fizz",'photos/recipes/Cranberry Fizz.jpg',6,"154 calories","5 minutes","In a pitcher, combine cranberry, orange and grapefruit juices and sugar. Refrigerate, covered, until chilled. Just before serving, stir in ginger ale. To serve, pour mixture over ice. Garnish with orange slices and cranberries if desired."),
            ("Pineapple Iced Tea",'photos/recipes/Pineapple Iced Tea.jpg',6,"51 calories","15 minutes","In a large saucepan, bring water to a boil; remove from heat. Add tea bags; steep, covered, 3-5 minutes according to taste. Discard tea bags. Stir in sugar until dissolved. Transfer to a pitcher; cool slightly. Stir in fruit juices. Refrigerate, covered, overnight. Serve over ice. Garnish as desired.")]


def insert_ctg(arr):
    id = 1
    for name, category_image in arr:
        num_of_recipes = R.get_count_recipes_same_ctg(id)
        C.insert_category(name, num_of_recipes, category_image)
        id += 1

arr_categories=[("Appetizers",'photos/categories/Appetizers.jpg'),
                ("Soups",'photos/categories/Soups.jpg'),
                ("Main Dishes",'photos/categories/Main Dishes.jpeg'),
                ("Salads",'photos/categories/Salads.jpg'),
                ("Deserts",'photos/categories/Deserts.jpg'),
                ("Drinks",'photos/categories/Drinks.png')]
#___________________________________________________________

def insert_ing(arr):
    for ingredient,amount,id_i in arr:
        I.insert_ingredient(ingredient,amount,id_i)

arr_ingredients=[("Onion","1 medium",1),("Minced fresh chives","2 tablespoons",1),("Minced fresh basil","2 teaspoons",1),("Garlic cloves","2 pieces",1),("Salt","1/2 teaspoon",1),("Pepper","1/4 teaspoon",1),("Paprika","1 teaspoon",1),("Pork sausage","1-1/4 pounds",1),("Frozen puff pastry","1 package",1),
                 ("White chicken","1 can",2),("Vegetable cream cheese","1 carton",2),("Salsa","1 cup",2),("Cooked bacon","4 pieces",2),("Flour tortillas","6 pieces",2),
                 ("Olive oil","1 tablespoon",3),("Brown sugar","1-1/2 teaspoons",3),("Garlic clove","1 piece",3),("Lemon juice","1-1/2 teaspoons",3),("Paprika","1/2 teaspoon",3),("Dried basil","1/2 teaspoon",3),("Pepper","1/3 teaspoon",3),("Uncooked shrimp","1 pound",3),
                 ("Avocado","2 medium pieces",4),("Minced fresh cilantro","3 tablespoons",4),("Red chili peppers","2 pieces",4),("Salt","1/4 teaspoon",4),("Lime","2 small pieces",4),("French bread baguette","12 slices",4),
                 ("Skinless chicken breasts","1-1/2 pounds",5),("Sesame oil","1 tablespoon",5),("Carrots","3 medium",5),("Celery ribs","2 pieces",5),("Onion","1 medium",5),("Chicken broth","6 cups",5),("Teriyaki sauce","1/3 cup",5),("Shiitake mushrooms","2 cups",5),("Celery leaves","1/3 cup",5),("Fresh basil","1/4 cup",5),("Minced fresh cilantro","2 tablespoons ",5),("Green onions","2 pieces",5),
                 ("Frozen fully cooked Italian meatballs","16",6),("Fire-roasted diced tomatoes","1 can",6),("Italian seasoning","1/4 teaspoon ",6),("Pepper","1/4 teaspoon ",6),("Chicken stock","2 cartons",6),("Frozen cheese tortellini","2 cups ",6),("Fresh baby spinach","3 ounces",6),
                 ("Butter","2 tablespoons",7),("Onion","1 medium piece",7),("Potatoes","6 medium pieces",7),("Water","5 cups",7),("Milk 2%","2 cups ",7),("Condensed cream of chicken soup","1 can",7),("Garlic salt","1/2 teaspoon ",7),("Pepper","1/8 teaspoon",7),("Velveeta","12 ounces",7),("Fresh parsley","handful",7),
                 ("Onion","1 large piece",8),("Butter","3 tablespoons",8),("All-purpose flour","3 tablespoons",8),("Salt","1/2 teaspoon",8),("Whole milk","4 cups",8),("Colby-Monterey Jack cheese","2 cups",8),("Seasoned salad croutons","Few pieces",8),
                 ("Egg","1 large",9),("Milk 2%","1/2 cup",9),("Crushed saltine crackers","1-1/2 cups ",9),("Boneless pork loin chops","6 pieces",9),("Canola oil","1/4 cup",9),
                 ("Boneless skinless chicken breast halves","4 pieces",10),("Butter","4 tablespoons",10),("White wine","1/2 cup",10),("Heavy whipping cream","1/2 cup",10),("Minced fresh rosemary","1 tablespoon",10),
                 ("Parmesan cheese","1 cup",11),("Soft bread crumbs","2 cups",11),("Melted butter","1/2 cup",11),("Boneless skinless chicken breast halves","6 pieces",11),("Country-style mustard","1/2 cup",11),
                 ("Ground beef","1 pound",12),("Spaghetti sauce","28 ounces",12),("Frozen sausage or cheese ravioli","1 package",12),("Shredded part-skim mozzarella cheese","1-1/2 cups",12),("Minced fresh basil","Handful",12),
                 ("Bulk pork sausage","1 pound",13),("Onion","1 medium",13),("Carrots","2 medium",13),("Green pepper","1 medium",13),("Diced cooked potatoes","3 cups",13),("Salt","1/2 teaspoon",13),("Pepper","1/4 teaspoon",13),
                 ("Frozen grilled chicken breast strips","1 package",14),("Crumbled blue cheese","1 cup",14),("White wine vinegar","3 tablespoons",14),("Water","1 tablespoon",14),("Coarsely ground pepper","1/8 teaspoon",14),("Canola oil","1/4 cup",14),("Chopped romaine","8 cups",14),("Tomatoes","3 medium",14),("Bacon strips, cooked and crumbled","6 pieces",14),
                 ("Bunch romaine","1 large piece",15),("Olive oil","3/4 cup",15),("Red wine vinegar","3 tablespoons",15),("Worcestershire sauce","1 teaspoon",15),("Salt","1/2 teaspoon",15),("Ground mustard","1/4 teaspoon",15),("Garlic clove","1 large piece",15),("Fresh lemon","1/2 piece",15),("Shredded Parmesan cheese","1/4 to 1/2 cup",15),("Caesar-flavored or garlic croutons","By taste",15),
                 ("Tomatoes","4 medium pieces",16),("Fresh basil leaves","1/4 cup",16),("Fresh mozzarella cheese","1/2 pound",16),("Olive oil","2 tablespoons",16),("Balsamic vinegar","2 tablespoons",16),("Ground mustard","1 teaspoon",16),("Salt","1/8 teaspoon",16),("Pepper","1/8 teaspoon ",16),
                 ("Tomatoes","3 large",17),("Sweet onion","1 large",17),("Cucumber","1 large",17),("Olive oil","1/4 cup",17),("Cider vinegar","2 tablespoons",17),("Garlic clove","1 piece",17),("Minced fresh basil","1 teaspoon",17),("Minced chives","1 teaspoon",17),("Salt","1/2 teaspoon",17),
                 ("Tomatoes","4 large",18),("Thinly sliced English cucumbers","2-1/2 cups",18),("Red onion","1 small",18),("Olive oil","1/4 cup",18),("Red wine vinegar","3 tablespoons",18),("Salt","1/4 teaspoon",18),("Pepper","1/8 teaspoon",18),("Dried oregano","1/4 teaspoon",18),("Pitted Greek olives","3/4 cup",18),("Crumbled feta cheese","3/4 cup",18),
                 ("White cake mix","1 package",19),("Boiling water","1-1/2 cups",19),("Cherry gelatin","1 package",19),("Cream cheese","1 package",19),("Whipped topping","2 cups",19),("Fresh strawberries","4 cups",19),
                 ("Cream cheese","3 ounces",20),("Confectioners sugar","1/4 cup",20),("Almond or vanilla extract","1/8 to 1/4 teaspoon",20),("Individual graham cracker shells","2 pieces",20),("Cherry pie filling","1/4 cup",20),
                 ("Cubed butter","1/4 cup",21),("Semisweet chocolate","2 ounces",21),("Dry red wine","1-1/2 teaspoons",21),("Vanilla extract","1/2 teaspoon",21),("Egg","1 large",21),("Egg yolk","2 teaspoons",21),("Confectioners sugar","1/2 cup",21),("All-purpose flour","3 tablespoons ",21),("Ground ginger","1/8 teaspoon",21),("Ground cinnamon","1/8 teaspoon",21),
                 ("Apple cider","1 gallon",22),("Frozen lemonade concentrate","1 can",22),("Lemon","1 medium",22),("Spiced apple rings","4 pieces",22),
                 ("Cranberry juice","1 bottle",23),("Orange juice","1 cup",23),("Ruby red grapefruit juice","1 cup",23),("Sugar","1/2 cup",23),("Ginger ale","2 cups",23),
                 ("Water","4 cups",24),("Tea bags","7 pieces",24),("Sugar","2 tablespoons",24),("Unsweetened pineapple juice","1 cup",24),("Lemon juice","1/3 cup",24)]

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# recipes = {}
# #
# for index, recipe in enumerate(arr_recipes):
#     name = recipe[0]
#     recipes[index+1] = name
# # print(recipes)
#
# # Loop through array and replace numbers with recipe names
# for i in range(len(arr_ingredients)):
#     recipe_num = arr_ingredients[i][2]
#     recipe_name = recipes[recipe_num]
#     arr_ingredients[i] = (arr_ingredients[i][0], arr_ingredients[i][1], recipe_name)
#
#
# insert_rcp(arr_recipes)
# insert_ing(arr_ingredients)
# insert_ctg(arr_categories)
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


# U.insert_user("user1@gmail.com","user1","3456")
# U.insert_user("user2@gmail.com","user2","6789")
# U.insert_user("user3@gmail.com","user3","7654")
# U.insert_user("user4@gmail.com","user4","user0000")








