 # IOC SCANNER

 Проект для проверки IOC(IP, hash, url, Domen) через VirusTotal, позволяет выявлять опасные обьекты.


 ---

 ## Возможности

 Ip - адреса
 hash файлов(MD5, SHA1, SHA256)
 Домен
 Url


 Получение SSL информаций для IP, url
 Subject
 Issuer
 Статус
 Определение уровня риска 
 Вывод результата в JSON (IOC.json)

 
 ## Как использовать?
 

 С начало нам нужно создать текстовый файл командой (touch text.txt, если у вас линукс) дальше заполнить 
 его данными такими как IP,HASH,URL,DOMAIN
 
 ## Откуда взять API ключ?

 Его можно взять из сайта VirusTotal

 Заходите на сайт VirusTotal -> Регистрация -> API KEY -> Копировать -> Вставляете в этот кусок кода
 api_key = "Ваш ключ"

 ## Как скачать скрипт?

 git clone https://github.com/alisherqweyuz/Ioc-scanner.git\

 cd IOC-Scanner

 python -m venv venv
 
 На виндовс(venv\Scripts\activate)
 На линукс(source venv/bin/activate) 
 
 pip install requests
 
 python VirusTotal.py
