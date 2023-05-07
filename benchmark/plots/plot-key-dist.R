# Include the
library(funr)
main_script_dir <- get_script_path()
included_script_path <- file.path(main_script_dir, "common.R")
source(included_script_path)

# Create a data frame with the probability distribution
probabilities <- c(1 / 7, 2 / 7, 4 / 7)
categories <- 0:(length(probabilities) - 1)
df <- data.frame(categories, probabilities)

# Invert each value in the probabilities vector
irates <- 1 / probabilities

df_irates <- data.frame(categories, irates)

# Calculate the start and end times for each category's duration
df_irates$start <- 0
df_irates$end <- irates
df_irates <- df_irates[rownames(df_irates), ]



# Calculate the cumulative distribution function (CDF)
cdf <- cumsum(probabilities)
df$cdf <- cdf

# Create the probability distribution bar chart
bar_chart_prob <- ggplot(df, aes(x = categories, y = probabilities, fill = as.factor(categories))) +
    geom_bar(stat = "identity") +
    labs(x = "Key layer", y = "Prob. to sign", title = "Probability distribution", fill = "Category") +
    scale_x_continuous(expand = c(0, 0), breaks = c(0, 1, 2)) +
    scale_y_continuous(expand = c(0, 0), limits = c(0, 1.0)) +
    theme_cowplot(font_size = fsize) +
    theme(legend.position = "none")


step_chart_cdf <- ggplot(df) +
    geom_segment(aes(x = categories, xend = categories + 1, y = cdf, yend = cdf, color = as.factor(categories))) + # Default color
    # geom_point(data = df[-1,], aes(x = categories, y = cdf), size = 3) +  # Default color for filled circles
    # geom_point(data = df[-c(1, nrow(df)),], aes(x = categories, y = cdf - probabilities[categories > 0]), size = 3, shape = 1) +  # Default color for empty circles shifted down without the first one
    labs(x = "Key layer", y = "Prob. to sign", title = "Cumulative distribution") +
    theme_cowplot(font_size = fsize) +
    theme(legend.position = "none") +
    scale_x_continuous(expand = c(0, 0), breaks = c(0, 1, 2))


# Create the timeline plot
timeline_plot <- ggplot(df_irates, aes(x = start, xend = end, y = as.factor(categories), yend = as.factor(categories), color = as.factor(categories))) +
    geom_segment(linewidth = 4, lineend = "butt") +
    scale_y_discrete(name = "Key layer", limits = rev(levels(as.factor(categories)))) +
    scale_x_continuous(name = "Inverse key sign rate", expand = c(0, 0), breaks = c(0, 1, 2, 3, 4, 5, 6, 7)) +
    labs(title = "Inverse key sign rate for layers", color = "Category") +
    theme_cowplot(font_size = fsize) +
    theme(legend.position = "none")

combined_plots <- grid.arrange(bar_chart_prob, step_chart_cdf, ncol = 2)

ggsave(paste(out_dir, "/", "key-dist-df", ".pdf", sep = ""), units = "in", width = half_w, height = 2, bar_chart_prob)
ggsave(paste(out_dir, "/", "key-dist-cdf", ".pdf", sep = ""), units = "in", width = half_w, height = 2, step_chart_cdf)
ggsave(paste(out_dir, "/", "key-dist-irates", ".pdf", sep = ""), units = "in", width = full_w, height = 1.15, timeline_plot)
