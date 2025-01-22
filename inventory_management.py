#!/usr/bin/env python
# coding: utf-8

# In[ ]:


get_ipython().system('jupyter nbconvert --to script inventory_management.ipynb')


# In[1]:


import os


# In[2]:


def view_inventory(inventory):
#Checks if the any inventory dictionary already exists - if it does not then inventory is empty
    if not inventory:
        print("Inventory is empty")
    else:
        for item,details in inventory.items():
            print(f"Item: {item}")
            print(f"Detail: {details}")
            for key, value in details.items():
                print(f"{key.capitalize()}: {value}")
            print("-" * 20)


# In[3]:


def add_inventory(inventory, name, quantity, price, description):
    if name in inventory:
        raise ValueError(f"{name} is already in inventory")
    else: 
        inventory[name] = {"quantity" : quantity,
                           "price": price,
                           "description":description
                          }
    print(f"{name} has been successfully added to inventory")
    


# In[4]:


def update_item(inventory, name, quantity, price, description):
    if name not in inventory:
        raise ValueError(f"{name} not found in inventory")
    else:
        if quantity is not None and quantity>=0:
            inventory[name]['quantity'] = quantity
        if price is not None and price>=0:
            inventory[name]['price'] = price
        if description is not None:
            inventory[name]['description'] = description
    print(f"{name} has been successfully updated")


# In[5]:


def remove_item(inventory, name):
    if name in inventory:
        choice = input(f"Are you sure if you want to delete {name}? 0 for No, 1 for Yes") 
        if choice == '1':
            del inventory[name]
        else:
            pass
    else:
        print(f"{name} not found in inventory")


# In[6]:


def bulk_remove(inventory, removals):
    items_to_remove = list(removals.keys())
    choice = input(f"Are you sure if you want to delete {items_to_remove}? 0:No,1:Yes")
    if choice == '1':
        for name, details in removals.items():
            if name in inventory:
                del inventory[name]
            else: 
                print(f"{name} not found in inventory")
    else:
        pass
        


# In[7]:


def bulk_add_inventory(inventory, new_inventory):
    for name, details in new_inventory.items():
        for key, value in details.items():
            if key == "quantity":
                quantity = value
            if key == 'price':
                price = value
            if key == 'description':
                description = value
        print(f"Name: {name}")
        print(f"Price: {price}")
        print(f"Quantity: {quantity}")
        print(f"Description: {description}")
        add_inventory(inventory, name, quantity, price, description)
        print('-' * 200) 
        


# In[11]:


def search_item(inventory, name):
    if name in inventory:
        print(f"Item: {name}")
        for key, value in inventory[name].items():
            print(f"  {key.capitalize()}: {value}")
    else:
        print(f"Item '{name}' not found.")


# In[ ]:


def main():
    import pickle
    if os.path.exists('inventory.pickle') is True:
        try:
            with open('inventory.pickle', "rb") as file:
                inventory = pickle.load(file)
        except FileNotFoundError:
            print("The file inventory.pickle does not exist.")
        except pickle.UnpicklingError:
            print("Error occurred while unpickling the file.")
    else:
        inventory = {}
        with open('inventory.pickle', "wb") as file:
            pickle.dump(inventory, file)

    while True:
        print("\nInventory Management System")
        print("1. View Inventory")
        print("2. Add Item")
        print("3. Update Item")
        print("4. Remove Item")
        print("5. Search for Item")
        print("6. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            view_inventory(inventory)
        elif choice == '2':
            name = input("Enter item name: ")
            quantity = int(input("Enter quantity: "))
            price = float(input("Enter price: "))
            description = input("Enter description: ")
            add_inventory(inventory, name, quantity, price, description)
        elif choice == '3':
            name = input("Enter item name to update: ")
            quantity = input("Enter new quantity (or leave blank): ")
            price = input("Enter new price (or leave blank): ")
            description = input("Enter new description (or leave blank): ")
            update_item(
                inventory,
                name,
                int(quantity) if quantity else None,
                float(price) if price else None,
                description if description else None
            )
        elif choice == '4':
            name = input("Enter item name to remove: ")
            remove_item(inventory, name)
        elif choice == '5':
            name = input("Enter item name to search: ")
            search_item(inventory, name)
        elif choice == '6':
            print("Exiting system. Goodbye!")
            try:
                with open('inventory.pickle', "wb") as file:  # Open the file in binary write mode
                    pickle.dump(inventory, file)  # Serialize and write the object to the file
                    print("Data saved successfully to inventory.pickle.")
            except pickle.PicklingError:
                print("Error occurred while pickling the data.")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()


# In[ ]:


inventory = {
    "Laptop": {"quantity": 10, "price": 999.99, "description": "High-end gaming laptop"},
    "Mouse": {"quantity": 50, "price": 19.99, "description": "Wireless mouse",
    "Phone": {"quantity": 10, "price": 999.99, "description": "iPhone 9S with 10x Lens Camera"},
    "Gaming Console": {"quantity": 50, "price": 499.99, "description": "Playstation 5 Console"}
}

