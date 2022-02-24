package com.javatechie.aws.cicd.example;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
@Entity(name="parts_blacklist")
public class PartBlacklist {
    @Id
    @GeneratedValue
    private int id;
    @Column
    private String dealer_id;
    public int getId() {
        return id;
    }
    public void setId(int id) {
        this.id = id;
    }
    public String getDealer_id() {
        return dealer_id;
    }
    public void setDealer_id(String dealer_id) {
        this.dealer_id = dealer_id;
    }
}