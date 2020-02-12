package com.rob.movieratingservice.model;

public class Movie {
    private int id;
    private String name;

    public Movie() {
    }

    public Movie(int i, String name) {
        this.id= id;
        this.name= name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
