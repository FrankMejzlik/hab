
library(funr)
main_script_dir <- get_script_path()
included_script_path <- file.path(main_script_dir, "common.R")
source(included_script_path)

max_y <- NA
max_x <- NA

data <- read.table(paste(data_dir, "/sec_oh_tradeoff.tsv", sep = ""), header = TRUE, sep = "\t", stringsAsFactors = FALSE)

# Convert the 'instance' and 'bit_sec' columns to factors
data$instance <- as.factor(data$instance)
data$bit_sec <- as.factor(data$bit_sec)

max_y <- max(data$oh)

# Create a custom color palette
color_palette <- colorRampPalette(c(theme_red, theme_blue, theme_green))(length(unique(data$bit_sec)))

# Custom labels formatter for y-axis
k_format <- function(x) {
  sapply(x, function(x) ifelse(x >= 1024, paste0(round(x/1024), "KiB"), x))
}

# Create the line chart
chart <- ggplot(data, aes(x = pks, y = oh, group = instance, color = bit_sec)) +
    theme_cowplot(font_size = fsize) +
    geom_line(linewidth = 1, alpha = 1) +
    coord_cartesian(xlim = c(0, max_x), ylim = c(0, max_y), expand = FALSE) +
	scale_y_continuous(labels = k_format, breaks = seq(0, max_y, by = max_y/5)) +
    scale_color_manual(values = color_palette) +
    labs(
        x = "Number of pubkeys in each piece",
        y = "Piece overhead",
		color = "Bit security"
    ) + 
    theme(legend.position = c(0.02, 0.7)) # Move the legend inside the chart



ggsave(paste(out_dir, "/", "sec_oh_tradeoff", ".pdf", sep = ""), units = "in", width = full_w, height = 2.5, chart)
