library(ggplot2)
library(cowplot)
library(reshape2)
library(dplyr)
library(stringr)
library(gtable)
library(grid) 
library(gridExtra)
library(patchwork)
library(funr)

main_script_dir <- get_script_path()


fsize <- 10
out_dir <- paste(main_script_dir, "/out/", sep="")
data_dir <- paste(main_script_dir, "/data/", sep="")
full_w <- 5.5
half_w <- 2.7


theme_red <- "#F8766D"
theme_red_light <- "#ffc1bc"
theme_green <- "#00BA38"
theme_green_light <- "#00ff4c"
theme_blue <- "#619CFF"

