<?php



namespace Securinets\UsersBundle\Entity;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;


use Doctrine\ORM\Mapping as ORM;

/**
 * User
 *
 * @ORM\Table()
 * @ORM\Entity(repositoryClass="Securinets\UsersBundle\Entity\UserRepository")
 */
class User implements AdvancedUserInterface, \Serializable {
	/**
	 * @var integer
	 *
	 * @ORM\Column(name="id", type="integer")
	 * @ORM\Id
	 * @ORM\GeneratedValue(strategy="AUTO")
	 */
	private $id;

	/**
	 * @var string
	 *
	 * @ORM\Column(name="username", type="string", length=25 , unique=true)
	 */
	private $username;

	/**
	 * @var string
	 *
	 * @ORM\Column(name="name", type="string", length=25 )
	 */
	private $name;	
	
	/**
	 * @var string
	 *
	 * @ORM\Column(name="firstname", type="string", length=25 )
	 */
	private $firstname;
	
	/**
	 * @var string
	 *
	 * @ORM\Column(name="salt", type="string", length=255)
	 */
	private $salt;

	/**
	 * @var string
	 *
	 * @ORM\Column(name="password", type="string", length=255)
	 */
	private $password;

	/**
	 * @var string
	 *
	 * @ORM\Column(name="email", type="string", length=60 )
	 */
	private $email;

	/**
	 * @var boolean
	 *
	 * @ORM\Column(name="isActive", type="boolean")
	 */
	private $isActive;

	/**
	 * @var integer
	 *
	 * @ORM\Column(name="score", type="integer" , nullable = true)
	 */
	private $score;

	/**
	 * @var \DateTime
	 *
	 * @ORM\Column(name="time", type="time" , nullable=true)
	 */
	private $time;

	/** 
	 * @ORM\Column(name="roles", type="array")
	 */
	private $roles;
	
	/**
	 * @ORM\OneToMany(targetEntity="Securinets\FrontOfficeBundle\Entity\EpreuveChallenger", mappedBy="user")
	 */
	private $epreuves;
	
	/**
	 * @ORM\OneToMany(targetEntity="Securinets\FrontOfficeBundle\Entity\Flag", mappedBy="equipe")
	 */
	private $flags;
	
	/**
	 * @ORM\OneToMany(targetEntity="Securinets\FrontOfficeBundle\Entity\ValidatedFlag", mappedBy="equipe")
	 */
	private $Validatedflags;
	
	/**
	 * @ORM\Column(name="avertLevel1" , type="integer" , nullable= true )
	 */
	private $avertLevel1;
	
	/**
	 * Get id
	 *
	 * @return integer 
	 */
	public function getId() {
		return $this->id;
	}

	/**
	 * Set username
	 *
	 * @param string $username
	 * @return User
	 */
	public function setUsername($username) {
		$this->username = $username;

		return $this;
	}

	/**
	 * Get username
	 *
	 * @return string 
	 */
	public function getUsername() {
		return $this->username;
	}

	/**
	 * Set salt
	 *
	 * @param string $salt
	 * @return User
	 */
	public function setSalt($salt) {
		$this->salt = $salt;

		return $this;
	}

	/**
	 * Get salt
	 *
	 * @return string 
	 */
	public function getSalt() {
		return $this->salt;
	}

	/**
	 * Set password
	 *
	 * @param string $password
	 * @return User
	 */
	public function setPassword($password) {
		$this->password = $password;

		return $this;
	}

	/**
	 * Get password
	 *
	 * @return string 
	 */
	public function getPassword() {
		return $this->password;
	}

	/**
	 * Set email
	 *
	 * @param string $email
	 * @return User
	 */
	public function setEmail($email) {
		$this->email = $email;

		return $this;
	}

	/**
	 * Get email
	 *
	 * @return string 
	 */
	public function getEmail() {
		return $this->email;
	}

	/**
	 * Set isActive
	 *
	 * @param boolean $isActive
	 * @return User
	 */
	public function setIsActive($isActive) {
		$this->isActive = $isActive;

		return $this;
	}

	/**
	 * Get isActive
	 *
	 * @return boolean 
	 */
	public function getIsActive() {
		return $this->isActive;
	}

	/**
	 * Set score
	 *
	 * @param integer $score
	 * @return User
	 */
	public function setScore($score) {
		$this->score = $score;

		return $this;
	}

	/**
	 * Get score
	 *
	 * @return integer 
	 */
	public function getScore() {
		return $this->score;
	}

	/**
	 * Set time
	 *
	 * @param \DateTime $time
	 * @return User
	 */
	public function setTime($time) {
		$this->time = $time;

		return $this;
	}

	/**
	 * Get time
	 *
	 * @return \DateTime 
	 */
	public function getTime() {
		return $this->time;
	}
	
	
	public function getRoles() {
		
		return $this->roles ;

	}
	public function eraseCredentials() {
		// TODO: Auto-generated method stub

	}
	
	public function serialize()
	{
		return serialize(array(
				$this->id,
		));
	}
	
	public function unserialize($serialized)
	{
		list (
				$this->id,
		) = unserialize($serialized);
	}
	
	public function isEqualTo(UserInterface $user)
	{
		return $this->username === $user->getUsername();
	}


    /**
     * Set roles
     *
     * @param array $roles
     * @return User
     */
    public function setRoles($roles)
    {
        $this->roles = $roles;
    
        return $this;
    }
    
    public function isAccountNonExpired()
    {
    	return true;
    }
    
    public function isAccountNonLocked()
    {
    	return true;
    }
    
    public function isCredentialsNonExpired()
    {
    	return true;
    }
    
    public function isEnabled()
    {
    	return $this->isActive;
    }
    
    public function __construct()
    {
    	$this->score = 0 ;
    	$this->roles= array('ROLE_CHALLENGER');
    	$this->salt = base_convert(sha1(uniqid(mt_rand(), true)), 16, 36) ;
    }

    /**
     * Set name
     *
     * @param string $name
     * @return User
     */
    public function setName($name)
    {
        $this->name = $name;
    
        return $this;
    }

    /**
     * Get name
     *
     * @return string 
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set firstname
     *
     * @param string $firstname
     * @return User
     */
    public function setFirstname($firstname)
    {
        $this->firstname = $firstname;
    
        return $this;
    }

    /**
     * Get firstname
     *
     * @return string 
     */
    public function getFirstname()
    {
        return $this->firstname;
    }

    /**
     * Add epreuves
     *
     * @param \Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuves
     * @return User
     */
    public function addEpreuve(\Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuves)
    {
        $this->epreuves[] = $epreuves;
    
        return $this;
    }

    /**
     * Remove epreuves
     *
     * @param \Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuves
     */
    public function removeEpreuve(\Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuves)
    {
        $this->epreuves->removeElement($epreuves);
    }

    /**
     * Get epreuves
     *
     * @return \Doctrine\Common\Collections\Collection 
     */
    public function getEpreuves()
    {
        return $this->epreuves;
    }

    /**
     * Add epreuveChallengers
     *
     * @param \Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuveChallengers
     * @return User
     */
    public function addEpreuveChallenger(\Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuveChallengers)
    {
        $this->epreuveChallengers[] = $epreuveChallengers;
    
        return $this;
    }

    /**
     * Remove epreuveChallengers
     *
     * @param \Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuveChallengers
     */
    public function removeEpreuveChallenger(\Securinets\FrontOfficeBundle\Entity\EpreuveChallenger $epreuveChallengers)
    {
        $this->epreuveChallengers->removeElement($epreuveChallengers);
    }

    /**
     * Get epreuveChallengers
     *
     * @return \Doctrine\Common\Collections\Collection 
     */
    public function getEpreuveChallengers()
    {
        return $this->epreuveChallengers;
    }

    /**
     * Set avertLevel1
     *
     * @param integer $avertLevel1
     * @return User
     */
    public function setAvertLevel1($avertLevel1)
    {
        $this->avertLevel1 = $avertLevel1;
    
        return $this;
    }

    /**
     * Get avertLevel1
     *
     * @return integer 
     */
    public function getAvertLevel1()
    {
        return $this->avertLevel1;
    }


    /**
     * Add flags
     *
     * @param \Securinets\FrontOfficeBundle\Entity\Flag $flags
     * @return User
     */
    public function addFlag(\Securinets\FrontOfficeBundle\Entity\Flag $flags)
    {
        $this->flags[] = $flags;
    
        return $this;
    }

    /**
     * Remove flags
     *
     * @param \Securinets\FrontOfficeBundle\Entity\Flag $flags
     */
    public function removeFlag(\Securinets\FrontOfficeBundle\Entity\Flag $flags)
    {
        $this->flags->removeElement($flags);
    }

    /**
     * Get flags
     *
     * @return \Doctrine\Common\Collections\Collection 
     */
    public function getFlags()
    {
        return $this->flags;
    }

    /**
     * Add Validatedflags
     *
     * @param \Securinets\FrontOfficeBundle\Entity\ValidatedFlag $validatedflags
     * @return User
     */
    public function addValidatedflag(\Securinets\FrontOfficeBundle\Entity\ValidatedFlag $validatedflags)
    {
        $this->Validatedflags[] = $validatedflags;
    
        return $this;
    }

    /**
     * Remove Validatedflags
     *
     * @param \Securinets\FrontOfficeBundle\Entity\ValidatedFlag $validatedflags
     */
    public function removeValidatedflag(\Securinets\FrontOfficeBundle\Entity\ValidatedFlag $validatedflags)
    {
        $this->Validatedflags->removeElement($validatedflags);
    }

    /**
     * Get Validatedflags
     *
     * @return \Doctrine\Common\Collections\Collection 
     */
    public function getValidatedflags()
    {
        return $this->Validatedflags;
    }
}