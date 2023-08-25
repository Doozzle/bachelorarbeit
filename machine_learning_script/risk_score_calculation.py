import pyodbc
import numpy as np
from sklearn.cluster import OPTICS

#Variable definition complete script
riskfull_addresses = []
mac_addresses = []

#Establish Connection to the Database
connection = pyodbc.connect('Driver={ODBC Driver 18 for SQL Server};Server=tcp:network-watching.database.windows.net,1433;Database=network-watching;Uid=Adminuser;Pwd=!Trompete31012002!4;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;')
cursor = connection.cursor()

#Get all MAC-addresses from the Database
cursor.execute("SELECT * FROM dbo.web_reputation;")
while True:
    row = cursor.fetchone()
    if row == None:
        break
    if row.mac_addr not in mac_addresses:
        mac_addresses.append(row.mac_addr)

#Perform the steps for calculating the risk score for each address in the dataset
for address in mac_addresses:
    #Variable definition for the risk score calculation
    X = np.array([])
    number_of_clusters = 0
    number_of_outliers = 0
    historic_number_clusters = []
    historic_number_outliers = []
    sum_clusters = 0
    sum_outliers = 0
    risk_status = "no-risk"

    #Extract all Session data from the web_reputation database
    cursor.execute("SELECT * FROM dbo.web_reputation WHERE mac_addr = " + str(address)+";")

    #Write all the Data from the SELECT statement into a numpy array to perform clustering later on
    while True:
        row = cursor.fetchone()
        if row == None:
            break
        X.append([row.date, row.time, row.web_rep_score], axis = 0)

    #Perform the actual Clustering. Minimum of 3 samples fits best in the test case, may be different in future implementations
    clustering = OPTICS(min_samples=3).fit(X)

    #Scan for the highest Clusterlabel as well as the number of outliers (-1's)
    for i in np.nditer(clustering.labels_):

        #Check number of Clusters
        if i > number_of_clusters:
            number_of_clusters = i
        
        #Check for Outliers
        if i == -1:
            number_of_outliers += 1

    #Increasing the number of clusters by 1 as they are count from 0
    number_of_clusters += 1

    #Retrieve the data about historic number of clusters an outliers from the database
    cursor.execute("SELECT * FROM dbo.cluster_data WHERE mac_addr = " + str(address)+";")
    while True:
        row = cursor.fetchone()
        if row == None:
            break
        historic_number_clusters.append(row.clusters)
        historic_number_outliers.append(row.outliers)


    #Check if there is any historical data of the MAC-address within the database. If either one of the historic arrays is empty, there is no data available for both.
    if historic_number_clusters != []:

        #Calculating the mean of the historic data of clusters and outliers
        for i in historic_number_clusters:
            sum_clusters += i
        for i in historic_number_outliers:
            sum_outliers += i
        mean_clusters = sum_clusters / len(historic_number_clusters)
        mean_outliers = sum_outliers / len(historic_number_outliers)

        #Check wether the difference in the number of clusters and outliers is relevant (> 10%) and set the risk_status appropriately
        if number_of_clusters > (mean_clusters * 1.1) or number_of_outliers > (mean_outliers * 1.1):
            print("ALERT: Client with MAC-address: " + address + " is showing suspicious behaviour!")
            risk_status = "risk"
            riskfull_addresses.append(address)
        
    #Write the new data into the database
    cursor.execute("INSERT INTO dbo.cluster_data VALUES ('"+str(address)+"', '"+str(number_of_clusters)+"', '"+str(number_of_outliers)+"', '"+risk_status+"');")
    connection.commit()
    print("Database updated!")
    print("############################")

#After performing clustering for all of the known addresses, print all the riskfull Clients
print("The following addresses show riskfull behaviour:")
for i in riskfull_addresses:
    print("MAC-address: " + i)
