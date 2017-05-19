
# coding: utf-8

# In[1]:

from bs4 import BeautifulSoup
import requests
url="https://www.symantec.com/security_response/landing/vulnerabilities.jsp"


# In[ ]:

#I imported beautifulsoup in order to perform web data scraping using python.


# In[2]:

response = requests.get(url)
content = response.content


# In[ ]:

#I have extracted the data from the url. But, the data is unstructured.


# In[3]:

soup = BeautifulSoup(content, "lxml")


# In[ ]:

#I used beautifulsoup function to extract the data from the content in lxml format.


# In[4]:

tables = soup.find("div", {'class':'bckSolidWht bckPadLarge clearfix'}).find_all('table')


# In[ ]:

#I want to extract the data related to tables.


# In[6]:

rows = tables[0].findAll('tr')
severity_value = []
vul_value = []
date_value = []
url_values = []
for tr in rows:
    if "Discovered" not in tr(text=True):
        severity = tr.find('img')['title']
        severity_value.append(severity)
        
        
        a_tag = tr.find('a')
        vul = a_tag(text=True)[0]
        vul = str(vul.replace("u'"," "))
        vul_value.append(vul)
        
        url_values.append("https://www.symantec.com/" + a_tag['href'])
        
        td = tr.findAll('td')[2]
        date_ = td.find(text=True)
        date = str(date_.replace("u'"," "))
        date_value.append(date)
        
       


# In[ ]:

#I want to extract the data in table-1 except the first row.


# In[8]:

from datetime import datetime


# In[ ]:

#I imported datetime in order to convert date_value[index] string to datetime object in python.


# In[14]:

import re
user_severity = int(input("Enter the severity level equal to or above: "))
date_start = raw_input("Enter start date: format - 2015/8/15:  ")
date_end = raw_input("Enter end date: format - 2016/5/13: ")
w = raw_input("Type the word or phrase you look for:")
a = datetime.strptime(str(date_start),"%Y/%m/%d")
z = datetime.strptime(str(date_end), "%Y/%m/%d")
for i in range(len(vul_value)):
    data = datetime.strptime(date_value[i], "%m/%d/%Y")
    if int(severity_value[index]) > user_severity - 1:
        if (data > a) & (data < z) :
            if (vul_value[i].count(w)) > 0:
                print(vul_value[i])
                


# In[ ]:

#In the above cell, I tried to extract the vulnerabilities based on start date, end date, severity level, and word.
#Thus, the above cell fulfills the requirement of assignment.


# In[15]:

import re
count = 1
k = raw_input("enter term you are looking for in description: ")
for index in xrange(100):
    url = url_values[index]
    response = requests.get(url)
    content = response.content
    soup = BeautifulSoup(content,'lxml')
    desc_line = soup.find("div",{'class':'fontXLG'}).findAll('div')[-1]
    for child in desc_line.stripped_strings:
        child = re.sub('\Description$', '', child.rsplit('\n',1)[0])
        child = re.sub(' +',' ',child).rstrip(' ')
    
    if (child.count(str(k)) > 0):
            date = datetime.strptime(date_value[index], '%m/%d/%Y').strftime('%A %d. %B %Y')
            line1 = "\nFound Vulnerability Number " + str(count) + " in row " + str(index+1) + "\t < " + date + " >"
            line2 = child + url_values[index]
            print(line1)
            print(line2)
            count += 1


# In[ ]:

#In the above cell, I tried to extract the url data as well as url link description based on the search word.
#Thus, the above cell fullfills the requirement-2 of the assignment.

