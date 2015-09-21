# Vetted

Currently being developed on ubuntu 14.04 using postgres 9.4 and flask.

### Overview

The idea behind this project is to create a simple indicator management app that is able to provide security analysts with a workflow to easily research, create, contextualize, and store threat detections. Once those detections have been vetted, they are available via api in the below json format, which could then be pulled down to a detection device for consumption. For more info check out the documentation.html page found in the welcome template dir.  

### JSON format

```
{
  "created_date": "", 
  "indicators": [
    {
      "": ""
    }, 
  ],
  "notes": "", 
  "source": "", 
  "tags": [
    ""
  ]
}
```

### Detection types

Supported detection types: 'Bro Intel', 'Snort', 'Yara'.

### API clients

As of now, I only have the Bro Intel api client working.

### Installing

Getting this spun up is a manual process. For more info check out the INSTALL doc.

### Misc

- Auto converts pdfs, and cleans docx and html file types before scraping atomic indicators from those sources for the Bro Intel detection type. Also scrapes keywords, which are added as tags to the associated detection object(s).

- research module has an rss and atom feed parser. 

- RBAC: admin, user

### Screenshots

![welcome](./screens/welcome.png)
![feeds](./screens/feeds.png)
![auto_create](./screens/auto_create.png)
![manual](./screens/manual.png)
![vetted](./screens/vetted.png)
![editintel](./screens/editintel.png)

### To do:
- add "memory - yara" detection object
- snort api client, yara bin/mem api client
- more research modules
- task queue
- code has a lot of stank... i'll get around to that one day
- easy install script


any questions or feedback, feel free to send me an email reed3276@gmail.com

