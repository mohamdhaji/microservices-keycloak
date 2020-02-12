package com.rob.movieratingservice.controller;

import com.rob.movieratingservice.model.Movie;
import com.rob.movieratingservice.service.MovieService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/movierating")
public class MovieRatingController {

    @Autowired
    private MovieService movieService;

    @GetMapping("/{movieId}")
    public Movie getMovieRating(@PathVariable(name = "movieId", required = true) int movieId){
        return movieService.getMovie(movieId);
    }
}
