package com.javatechie.aws.cicd.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/test")
public class OrderServiceApplication {

    @Autowired
    PartBlacklistRespository partBlacklistRespository;
    @GetMapping
    public List<PartBlacklist> testIt(){
        System.out.println("PArts black list size:-----"+ partBlacklistRespository.findAll().size());
        return partBlacklistRespository.findAll();
    }
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
}