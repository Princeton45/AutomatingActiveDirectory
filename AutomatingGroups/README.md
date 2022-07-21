This Powershell script does the following:

  1) Loads in the XML file which states the different groups and titles within the Active Directory.
  2) Looks up the group.
  3) Creates the group if it doesn't exist.
  4) Add and remove anyone as needed from the group based on the their title.
  
  
 Day 1) Created a function to validate the groups.
  -Takes in XML File and validates whether the groups exist
  
  Day 2) Adding in a parameter called "create" 
   - Creates the group if it doesn't exist
    - If we don't pass the parameter, it wont pass the groups by default.
