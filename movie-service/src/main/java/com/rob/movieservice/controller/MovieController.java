package com.rob.movieservice.controller;

import com.rob.movieservice.model.Movie;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/movies")
public class MovieController {

    @GetMapping
    public List<Movie> allMovies(){
        return Arrays.asList(new Movie(1, "Sholey"), new Movie(2, "Shool"));
    }

    @GetMapping("{id}")
    public Movie getMovie(@PathVariable(name = "id", required = true) int id){
        return new Movie(id, "Movie-"+id);
    }
}
