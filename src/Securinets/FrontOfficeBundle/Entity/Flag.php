<?php

namespace Securinets\FrontOfficeBundle\Entity;

use Doctrine\ORM\Mapping as ORM;


/**
 * 
 * @ORM\Entity
 *@ORM\Table()
 *
 */
class Flag {
	
	/**
	 * @ORM\Column(name="flag", type="string" , length = 32)
	 * @ORM\Id
	 */
	private $flag ;
	
	/**
	 * @ORM\ManyToOne(targetEntity = "Securinets\UsersBundle\Entity\User" , inversedBy="flags")
	 */
	private $equipe ;


	/**
	  * @ORM\Column(name="points" , type ="integer" , nullable =true )
	  */
	private $points ;
	
	/**
	 * @ORM\OneToMany(targetEntity="Securinets\FrontOfficeBundle\Entity\ValidatedFlag", mappedBy="flag")
	 */
	private $Validatedflags;
	
	
	/**
	 * @ORM\Column(name="validated" , type="boolean")
	 */
	private $validated ;
    
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->Validatedflags = new \Doctrine\Common\Collections\ArrayCollection();
        $this->validated = false ;
    }
    
    /**
     * Set flag
     *
     * @param string $flag
     * @return Flag
     */
    public function setFlag($flag)
    {
        $this->flag = $flag;
    
        return $this;
    }

    /**
     * Get flag
     *
     * @return string 
     */
    public function getFlag()
    {
        return $this->flag;
    }

    /**
     * Set points
     *
     * @param integer $points
     * @return Flag
     */
    public function setPoints($points)
    {
        $this->points = $points;
    
        return $this;
    }

    /**
     * Get points
     *
     * @return integer 
     */
    public function getPoints()
    {
        return $this->points;
    }

    /**
     * Set equipe
     *
     * @param \Securinets\UsersBundle\Entity\User $equipe
     * @return Flag
     */
    public function setEquipe(\Securinets\UsersBundle\Entity\User $equipe = null)
    {
        $this->equipe = $equipe;
    
        return $this;
    }

    /**
     * Get equipe
     *
     * @return \Securinets\UsersBundle\Entity\User 
     */
    public function getEquipe()
    {
        return $this->equipe;
    }

    /**
     * Add Validatedflags
     *
     * @param \Securinets\FrontOfficeBundle\Entity\ValidatedFlag $validatedflags
     * @return Flag
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

    /**
     * Set validated
     *
     * @param boolean $validated
     * @return Flag
     */
    public function setValidated($validated)
    {
        $this->validated = $validated;
    
        return $this;
    }

    /**
     * Get validated
     *
     * @return boolean 
     */
    public function getValidated()
    {
        return $this->validated;
    }
}