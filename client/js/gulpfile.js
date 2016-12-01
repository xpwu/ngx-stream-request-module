/**
 * Created by xpwu on 2016/11/22.
 */

var gulp = require('gulp'),
  uglify = require('gulp-uglify'),
  concat = require('gulp-concat'),
  rename = require('gulp-rename');

gulp.task('client', function () {
  gulp.src(['stm.response.js', 'stm.contentprotocol.js', 'stm.defaultcontentprotocol.js', 'stm.client.js'])
    .pipe(concat('stm.clienttemp.js'))
    .pipe(rename('stm.client.js'))
    .pipe(gulp.dest('dest'))
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

gulp.task('default', ['client', 'stringview'], function() {
  // nothing
});
