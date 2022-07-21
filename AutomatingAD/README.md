# AutomatingActiveDirectory
This Powershell script does the following:

1) Takes in a CSV file full of employee data.
2) Compares the data in the CSV file to the employees in AD and seeing which ones need to be created, synced or deleted.
  2.a) Using compare functions to get user data based on the results to find out what user data to add, sync, or rename.
3) Will create any users and syncs the existing users, will make changes if it needs to.
  3.a) Will generate usernames and a password for when we want to create users.
    3.b) A function is used to generate a username based on last name and first initial.
4) Removes any deleted users.

