<?php

namespace Securinets\UsersBundle\Controller;

use Securinets\UsersBundle\Entity\User;

use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;


class DefaultController extends Controller
{
    
    public function loginAction()
    {
    	$request = $this->getRequest();
    	$session = $request->getSession();
    	
    	if ($this->get('security.context')->isGranted('IS_AUTHENTICATED_FULLY'))
    	{
    		return $this->redirect($this->generateUrl('home'));
    	}
    	
    	// get the login error if there is one
    	if ($request->attributes->has(SecurityContext::AUTHENTICATION_ERROR)) {
    		$error = $request->attributes->get(SecurityContext::AUTHENTICATION_ERROR);
    	} else {
    		$error = $session->get(SecurityContext::AUTHENTICATION_ERROR);
    		$session->remove(SecurityContext::AUTHENTICATION_ERROR);
    	}
    	
    	
    	return $this->render('SecurinetsUsersBundle:Default:login.html.twig', array(
    			// last username entered by the user
    			'last_username' => $session->get(SecurityContext::LAST_USERNAME),
    			'error'         => $error
    	));    	
    }
    
    
    public function registerAction() {
	   	
    	//l'objet user
    	$user = new User();
    	//appel de service
    	$encoder = $this->container->get('security.encoder_factory')->getEncoder($user);
    	//setting up the user
    	$user->setIsActive(true)
    	->setScore(0)
    	->setRoles(array('ROLE_CHALLENGER'))
    	->setTime(null)
    	->setSalt(base_convert(sha1(uniqid(mt_rand(), true)), 16, 36));
    	//creation du formulaire
    	$formBuilder = $this->createFormBuilder($user);
    	//ajout des champs voulu
    	$formBuilder
    	->add('firstname','text')
    	->add('name','text')
    	->add('username','text')
    	->add('email',   'text')
    	->add('password','password');
    	//génération du formulaire
    	$form = $formBuilder->getForm();
    	// On récupère la requête
    	$request = $this->get('request');
    	// On vérifie qu'elle est de type POST
    	if ($request->getMethod() == 'POST') {
    		// On fait le lien Requête <-> Formulaire
    		// À partir de maintenant, la variable $user contient les valeurs entrées dans le formulaire par le visiteur
    		$form->bind($request);
    		// On vérifie que les valeurs entrées sont correctes
    		 
    		if ($form->isValid()) {
    			// On l'enregistre notre objet $user dans la base de données
    			$em = $this->getDoctrine()->getManager();
    			 
    			$pass = $user->getPassword();
    			 
    			$user->setPassword($encoder->encodePassword($pass,$user->getSalt()));
    			try {
    				$em->persist($user);
    				$em->flush();
    				return $this->redirect($this->generateUrl('login'));
    			} catch (\Exception $e) {
    
    			}
    			 
    			 
    		}
    	}
    
    	return $this->render('SecurinetsUsersBundle:Default:register.html.twig', array('form' => $form->createView()));
    

    	
    }
     

}
