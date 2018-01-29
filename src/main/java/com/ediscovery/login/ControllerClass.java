package com.ediscovery.login;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/ediscovery")
public class ControllerClass {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public ControllerClass(UserRepo userRepo,
                          BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepo = userRepo;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostMapping("/signup")
    public void signUp(@RequestBody AppUser appUser) {
        System.out.println(appUser.getId());
        System.out.println(appUser.getUsername());
        System.out.println(appUser.getPassword());

        appUser.setPassword(bCryptPasswordEncoder.encode(appUser.getPassword()));
        System.out.println(appUser.getPassword());
        userRepo.save(appUser);
        System.out.println("inserted");
    }
   /*@PostMapping("/login")
   public void login(@RequestBody AppUser appUser ){

   }*/


    @RequestMapping("/welcome")
    public String welcome(){
        return "WELCOME";
    }

}


