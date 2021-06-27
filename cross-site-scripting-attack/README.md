# cross-site-scripting-attack  
This repository contains programs coded for the lab assignment **(offline-2)** on **cross-site scripting (XSS) attack**.  

**SEED Ubuntu VM** *(v16.04, 32bit)* provided by **SEEDLabs** was used as virtual lab environment. To demonstrate what attackers can do by exploiting **XSS** vulnerabilities, a web application named **Elgg** provided in the **pre-built Ubuntu VM image** was used. Basically, the vulnerabilities were exploited by launching an **XSS** attack on the modified version of **Elgg**.  

## navigation  
- `res` folder contains image which is used in the `README.md` file below  
- `spec` folder contains assignment specification with details on tasks  
- `src` folder contains 4 `.js` scripts corresponding to 4 tasks of this assignment  

## guidelines  
### setting up environment  
- log in to **Seed Ubuntu** and open up a terminal  
- type in `sudo service apache2 start` to start the **apache server**  
- visit `http://www.xsslabelgg.com` and be a **HACKERMAN** :)  

### user accounts in Elgg  
|   Name  | Username |   Password  |
|:-------:|:--------:|:-----------:|
|  Alice  |   alice  |  seedalice  |
|   Boby  |   boby   |   seedboby  |
| Charlie |  charlie | seedcharlie |
| Samy **(Attacker)**   | samy     | seedsamy    |  

## references  
- **set up SEED Ubuntu VM from this link:** https://seedsecuritylabs.org/lab_env.html  

## cross-site scripting (XSS) attack  
As you can see, everyone is devastated by the worm created by Samy.  

![xss-attack](https://github.com/FromSaffronCity/computer-security-sessional/blob/main/cross-site-scripting-attack/res/xss-attack.png?raw=true)  
