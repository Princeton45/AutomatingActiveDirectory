######################################

##Automating AD
##Date: July 8th, 2022
##By: Princeton Abdulsalam
##Automates Active Directory using PowerShell and a CSV file



#1. Load In the csv file for employees

function Get-EmployeeFromCsv{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string]$Delimiter,
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap
    )
    try{
        $SyncProperties=$SyncFieldMap.GetEnumerator()
        $Properties=ForEach($Property in $SyncProperties){
            @{Name=$Property.Value;Expression=[scriptblock]::Create("`$_.$($Property.Key)")}
        }
        Import-CSV -Path $FilePath -Delimiter $Delimiter | Select-Object -Property $Properties
    }catch{
        Write-Error $_.Exception.Message 
    }
}
#2. Load in the employees already in AD
function Get-EmployeesFromAD{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)] 
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$UniqueId 
    )
    
    try{
        Get-ADUser -Filter {$UniqueId -like "*"} -Server $Domain -Properties @($SyncFieldMap.Values) 
    
    }catch{
        write-Error -Message $_.Exception.Message
    }
}


Get-ADUser -Identity test -Server "int.acme.com" -Properties *

Get-ADUser -Filter {$UniqueId -like "*"} -Server "int.acme.com"

#3. Compare those
function Compare-Users{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)]
        [string]$UniqueId,
        [Parameter(Mandatory)]
        [string]$CSVFilePath,
        [Parameter()]
        [string]$Delimiter=",",
        [Parameter(Mandatory)]
        [string]$Domain
    
    )
    $CSVUsers=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter $Delimiter -SyncFieldMap $SyncFieldMap
    $ADUsers=Get-EmployeesFromAD -SyncFieldMap $SyncFieldMap -UniqueId $UniqueId -Domain $Domain

    Compare-Object -ReferenceObject $ADUsers -DifferenceObject $CSVUsers -Property $UniqueId -IncludeEqual
}

#Get the new users

#Get the synced users

#Get removed users
function Get-UserSyncData{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)]
        [string]$UniqueId,
        [Parameter(Mandatory)]
        [string]$CSVFilePath,
        [Parameter()]
        [string]$Delimiter=",",
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$OUProperty 
    )

    try{
    $CompareData=Compare-Users -SyncFieldMap $SyncFieldMap -UniqueID $UniqueId -CSVFilePath $CsvFilePath -Delimiter $Delimiter -Domain $Domain
    $NewUsersID=$CompareData | where SideIndicator -eq "=>"
    $SyncedUsersID=$CompareData | where SideIndicator -eq "=="
    $RemovedUsersID=$CompareData | where SideIndicator -eq "<="

    $NewUsers=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter $Delimiter -SyncFieldMap $SyncFieldMap | where $UniqueId -In $NewUsersID.$UniqueID 
    $SyncedUsers=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter $Delimiter -SyncFieldMap $SyncFieldMap | where $UniqueId -In $SyncedUsersID.$UniqueID
    $RemovedUsers=Get-EmployeesFromAD -SyncFieldMap $SyncFieldMap -Domain $Domain -UniqueId $UniqueId | where $UniqueId -In $RemovedUsersID.$UniqueID

    @{
        New=$NewUsers
        Synced=$SyncedUsers
        Removed=$RemovedUsers
        Domain=$Domain
        UniqueID=$UniqueId
        OUProperty=$OUProperty

    }

    }catch{
        Write-Error $_.Exception.Message
    }

    }

 function New-UserName{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$GivenName,
        [Parameter(Mandatory)]
        [string]$SurName,
        [Parameter(Mandatory)]
        [string]$Domain
    )
    
    [RegEx]$Pattern="\s|-|'"
    $index=1
    do{
        $Username="$Surname$($GivenName.Substring(0,$index))" -replace $Pattern,""
        $index++
    }while((Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain) -and ($Username -notlike "$Surname$Givenname"))
    
    if(Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain){
            throw "No usernames available for this user!"
    }else{
        $Username
    }
}

function Validate-OU{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)]
        [string]$CSVFilePath,
        [Parameter()]
        [string]$Delimiter=",",
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter()]
        [string]$OUProperty
    )
    try{
    $OUNames=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter "," -SyncFieldMap $SyncFieldMap | Select -Unique -Property $OUProperty

    foreach($OUName in $OUNames){
    $OUName=$OUName.$OUProperty
    if(-not(Get-ADOrganizationalUnit -Filter "name -eq '$OUName'" -Server $Domain)){
        New-ADOrganizationalUnit -Name $OUName -Server $Domain 
    }
        }
    }catch{
        Write-Error -Message $_.Exception.Message
}
}

function Create-NewUser{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$UserSyncData
    
    )
    try{
    $NewUsers=$UserSyncData.New

    foreach($NewUser in $NewUsers){
       Write-Verbose "Creating user : {$($NewUser.givenname) $($Newuser.surname)}"
       $Username=New-UserName -GivenName $NewUser.GivenName -Surname $Newuser.Surname -Domain $UserSyncData.Domain
       Write-Verbose "Creating user : {$($NewUser.givenname) $($Newuser.surname)} with username : {$Username}"
        if(-not($OU=Get-ADOrganizationalUnit -Filter "name -eq '$($NewUser.$($UserSyncData.OUProperty))'" -Server $UserSyncData.Domain)){
            throw "The organizational unit {$($NewUser.$($UserSyncData.OUProperty))}"
    }
    Write-Verbose "Creating user : {$($NewUser.givenname) $($Newuser.surname)} with username : {$Username}, {$ou)}"
    #Password section is below in case it needs to be changed 
    Add-Type -AssemblyName 'System.Web'
    $Password=[System.Web.Security.Membership]::GeneratePassword((Get-Random -Minimum 12 -Maximum 15),3)
    $SecuredPassword=ConvertTo-SecureString -String $Password -AsPlainText -Force

    $NewADUserParams=@{
        EmployeeID=$NewUser.EmployeeID
        GivenName=$NewUser.GivenName
        Surname=$NewUser.Surname
        Name=$Username
        SamAccountName=$Username
        UserPrincipalName="$Username@$($Usersyncdata.Domain)"
        AccountPassword=$SecuredPassword
        ChangePasswordAtLogon=$true
        Enabled=$true
        Title=$NewUser.Title
        Office=$NewUser.Office
        Path=$OU.DistinguishedName
        Confirm=$false
        Server=$UserSyncData.Domain

    }

    New-ADUser @NewADUserParams
    Write-Verbose "Created user: {$($NewUser.Givenname) $($NewUser.Surname)} EmpID: {$($NewUser.EmployeeID) Username: {$Username} Password: {$Password}"
    #End of Password section
    }  
    
   }catch{
        Write-Error $_.Exception.Message
   } 
}


 function Check-UserName{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$GivenName,
        [Parameter(Mandatory)]
        [string]$SurName,
        [Parameter(Mandatory)]
        [string]$CurrentUserName,
        [Parameter(Mandatory)]
        [string]$Domain
    )
    
    [RegEx]$Pattern="\s|-|'"
    $index=1

    do{
        $Username="$Surname$($GivenName.Substring(0,$index))" -replace $Pattern,""
        $index++
    }while((Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain) -and ($Username -notlike "$Surname$Givenname") -and ($Username -notlike $CurrentUserName))
    
    if((Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain) -and ($Username -notlike $CurrentUserName)){
            throw "No usernames available for this user!"
    }else{
        $Username
    }
}

function Sync-ExistingUsers{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$UserSyncData,
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap
    )
    $SyncedUsers=$UserSyncData.Synced

    foreach($SyncedUser in $SyncedUsers){
        write-Verbose "Loading data for $($SyncedUser.givenname) $($SyncedUser.surname)"
        $ADUser=Get-ADUser -Filter "$($UserSyncData.UniqueID) -eq $($SyncedUser.$($UserSyncData.UniqueID))" -Server $UserSyncData.Domain -Properties *
       
         if(-not($OU=Get-ADOrganizationalUnit -Filter "name -eq '$($SyncedUser.$($UserSyncData.OUProperty))'" -Server $UserSyncData.Domain)){
            throw "The organizational unit {$($SyncedUser.$($UserSyncData.OUProperty))}"
     }

      Write-Verbose "User is currently in $($ADUser.distinguishedname) but should be in $OU"
      if(($ADUser.DistinguishedName.split(",")[1..$($ADUser.DistinguishedName.Length)] -join ",") -ne ($OU.DistinguishedName)){
        Write-Verbose "OU needs to be changed"
        Move-ADObject -Identity $ADUser -TargetPath $OU -Server $UserSyncData.Domain
    }

      $ADUser=Get-ADUser -Filter "$($UserSyncData.UniqueID) -eq $($SyncedUser.$($UserSyncData.UniqueID))" -Server $UserSyncData.Domain -Properties *

      $Username=Check-UserName -GivenName $SyncedUser.GivenName -SurName $SyncedUser.Surname -CurrentUserName $ADUser.SamAccountName -Domain $UserSyncData.Domain

      if($ADUser.SamAccountName -notlike $Username){
        Write-Verbose "Username needs to be changed"
        Set-ADUser -Identity $ADUser -Replace @{userprincipalname="$Username@$($UserSyncData.Domain)"} -Server $UserSyncData.Domain
        Set-ADUser -Identity $ADUser -Replace @{samaccountname="$Username"} -Server $UserSyncData.Domain
        Rename-ADObject -Identity $ADUser -NewName $Username -Server $UserSyncData.Domain
      }

      $SetADUserParams=@{
        Identity=$Username
        Server=$UserSyncData.Domain
      }

      foreach($Property in $SyncFieldMap.Values){
        $SetADUserParams[$Property]=$SyncedUser.$Property
      }

      Set-ADUser @SetADUserParams

}
}

#Check if new users then create them
    #Needs a username, username needs to be unique; lastname, first intial username
    #Placing a user in a OU
    #Creating Users

#Check synced users
    #Check-username
    #Change OU
    #Update any other fields, position, office

#Check removed users, then disable them
function Remove-Users{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$UserSyncData,
        [Parameter()]
        [int]$KeepDisabledForDays=7
    )

    try{
        
    $RemovedUsers=$UserSyncData.Removed

    foreach($RemovedUser in $RemovedUsers){
        Write-Verbose "Fetching data for $($RemovedUser.Name)"
        $ADUser=Get-ADUser $RemovedUser -Properties * -Server $UserSyncData.Domain
        if($ADUser.Enabled -eq $true){
            Write-Verbose "Disabling user $($ADUser.Name)"
            Set-ADUser -Identity $ADUser -Enabled $false -AccountExpirationDate (Get-date).AddDays($KeepDisabledForDays) -Server $UserSyncData.Domain -Confirm:$false
    }else{
        if($ADUser.AccountExpirationDate -lt (get-date)){
            Write-Verbose "Deleting account $($ADUser.name)"
            Remove-ADUser -Identity $ADUser -Server $UserSyncData.Domain -Confirm:$false
        }else{
            Write-Verbose "Account $($ADUser.name) is still within the retention period."
        }
    }
}
    }catch{
        Write-Error -Message $_.Exception.Message
  }
}



$SyncFieldMap=@{
    EmployeeID="EmployeeID"
    FirstName="GivenName"
    LastName="SurName"
    Title="Title"
    Office="Office"
}
$CsvFilePath="C:\Employees.csv"
$Delimiter=","
$Domain="int.acme.com"
$UniqueId="EmployeeID"
$OUProperty="Office"
$KeepDisabledForDays=7

Validate-OU -SyncFieldMap $SyncFieldMap -CSVFilePath $CsvFilePath -Delimiter $Delimiter -Domain $Domain -OUProperty $OUProperty
$UserSyncData=Get-UserSyncData -SyncFieldMap $SyncFieldMap -UniqueId $UniqueId -CSVFilePath $CSVFilePath -Delimiter $Delimiter -Domain $Domain -OUProperty $OUProperty


Create-NewUser -UserSyncData $UserSyncData -Verbose

Sync-ExistingUsers -UserSyncData $UserSyncData -SyncFieldMap $SyncFieldMap -Verbose 

Remove-Users -UserSyncData $UserSyncData -KeepDisabledForDays $KeepDisabledForDays -Verbose