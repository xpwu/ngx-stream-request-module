/**
 * Created by xpwu on 2016/11/22.
 */

var gulp = require('gulp'),
  uglify = require('gulp-uglify'),
  rename = require('gulp-rename');

gulp.task('wsclient', function () {
  gulp.src('wsclient.js')
    .pipe(uglify())
    .pipe(rename({suffix: '.min'}))   //rename压缩后的文件名
    .pipe(gulp.dest('dest'));
});

gulp.task('stringview', function () {
  gulp.src('stringview.js')
    .pipe(uglify())
    .pipe(rename({suffix: '.min'}))   //rename压缩后的文件名
    .pipe(gulp.dest('dest'));
});

gulp.task('default', ['wsclient', 'stringview'], function() {
  // nothing
});
