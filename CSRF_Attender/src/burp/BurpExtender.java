package burp;
import java.io.PrintWriter;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Rudiger Morin-Docter & Thomas PEDROTTI
 * Petit Outil pour générer des attaques CSRF automatiquement pendant la naviguation sur notre site 'gentil'
 * ATTENTION il s'agit d'une version très basique, une sorte de Proof-of-Concept !
 */
public class BurpExtender implements IBurpExtender, IProxyListener //, IHttpListener
{
	private IExtensionHelpers helpers;
	PrintWriter stdout;
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) 
	{
		//Récupérer la Standard Output et les helpers de burp
		stdout = new PrintWriter(callbacks.getStdout(), true);
		helpers = callbacks.getHelpers();
		
		//Nous devenons le Listener de Proxy
		callbacks.registerProxyListener(this);
		
		//Donner un nom à notre Extension
		callbacks.setExtensionName("CSRF_Attender");
	}
	
	/**
	 * Permet d'écrire et d'obtenir des infos supplémentaires lors de l'utilisation de l'outil Proxy !
	 * Ici, nous allons récupérer la première ligne du header et la transformer en attaque CSRF potentielle (pour notre site...)
	 * En essayant d'automatiser le plus possible le processus
	 * @boolean messageIsRequest true si le message est une requête !
	 * @IInterceptedProxyMessage le message intercepté par le proxy !
	 */
	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
	{
		//On ne travaille que sur des requêtes !
		if(messageIsRequest)
		{
			//Récupérations des informations
			IHttpRequestResponse messageInfo = message.getMessageInfo();
			IRequestInfo rqInfo = helpers.analyzeRequest(messageInfo);
			List<String> headers = rqInfo.getHeaders();
			
			//Travailler sur la ligne qui nous intéresse !
			String startRequest = (String) headers.get(0);
			
			//Vérifier s'il s'agit d'une requête GET !
			if(isGetRequest(startRequest))
			{
				//On peut travailler dessus !
				
				//Modifier la requête de départ (on ne gère que les HTML1.1, pas les HTML2 !)
				String modifiedRequest = removeFirstChars(startRequest, 4);
				modifiedRequest = removeLastChars(modifiedRequest, 8);
				
				//Méthode : On affiche la requête capturée puis on crée le lien qui nous intéresse
				String siteHttp = new String("http://127.0.0.1");
				String generatedURL = siteHttp + modifiedRequest;
				
				//Dans l'invite de commande, on indique la génération dans un petit log d'attaques générées !
				stdout.println("CSRFAttender - Outil de génération d'un lien attaquant votre site gentil...\n"
						+ "Requête interceptée de départ : " + startRequest + "\n"
						+ "Génération d'un CSRF potentiel... \n"
						+ "Requête CSRF potentielle : " + generatedURL + "\n"
						+ "Essayez de modifier cette requête et de la lancer en tant qu'attaque CSRF pour voir l'effet potentiel sur votre site ! ;-) \n\n");
			}
			else
			{
				//On indique à l'utilisateur que l'on ne gère que les requêtes GET !
				stdout.println("CSRFAttender - Outil de génération d'un lien attaquant votre site gentil...\n"
						+ "ATTENTION - Ne fonctionne que pour les sites fonctionnant avec HTTP1.1 et sur les requêtes de type GET ! :-D \n");
			}
		}
	}
	
	/**
	 * Permet de retirer des characters au début d'un String
	 */
	public static String removeFirstChars(String s, int chars)
	{
		   return s.substring(chars);
	}
	
	/**
	 * Permet de retirer des characters à la fin d'un String
	 */
	public static String removeLastChars(String str, int chars) 
	{
	    return str.substring(0, str.length() - chars);
	}
	
	/**
	 * Méthode qui indique si la requête envoyée possède une méthode GET !
	 * @param request le string à analyser
	 * @return true si c'est une requête GET, false sinon
	 */
	public static boolean isGetRequest(String request)
	{
		Pattern p = Pattern.compile("GET");   // the pattern to search for
		Pattern p2 = Pattern.compile("HTTP/1.1");
	    Matcher m = p.matcher(request);
	    Matcher m2 = p2.matcher(request);
	    
	    //Si ça match alors c'est bon !
	    if (m.find() && m2.find())
	    {
	    	return true;
	    }
	    else
	    {
	    	return false;
	    }
	}
}
