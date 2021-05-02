# CSRF-Attender
CSRF Attender is a Burp Suite extension that illustrates a PoC for automatically generating CSRF attacks on a WebSite (works only for GET requests and HTTP1.1)

To use, Install Burp Suite Community (or Pro), go to the 'Extender' tab and Select 'Add'. Choose the CSRFAttender.jar and click 'Next'. There should be no Errors. Now browse your website using Burp's Chromium Browser and look at the results by selecting 'Output' -> 'Show in UI' in the 'Extender' Tab of Burp !

Feel free to look at the source code and try upgrading it !

So far it only uses the proxy tool from Burp Suite to capture the request headers and transform a GET request into a potential CSRF attack for the website you are currently browsing.
Definitely upgradable (I encourage anyone to try ! :D)

This Burp extension was made for a University project where we are immersed into the world of research.
University of Lorraine, UFR MIM, Master 1 Informatique.
