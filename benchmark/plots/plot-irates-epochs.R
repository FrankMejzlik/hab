library(funr)
main_script_dir <- get_script_path()
included_script_path <- file.path(main_script_dir, "common.R")
source(included_script_path)

max_y <- 1000
max_x <- 1500

files_list <- list(
	paste(data_dir, "/exp_base_reauth.tsv", sep=""),
	paste(data_dir, "/lin_base_reauth.tsv", sep=""),
	paste(data_dir, "/log_base_reauth.tsv", sep="")
)

# Read the data from the TSV file
data <- read.table(paste(data_dir, "base_irates.tsv", sep = ""), header = TRUE, sep = "\t")

# Create the stacked bar chart
chart <- ggplot(data, aes(x = layer, y = irate, fill = configuration)) +
    theme_cowplot(font_size = fsize) +
    geom_bar(stat = "identity", alpha = 0.5, position = "identity") +
    scale_fill_manual(values = c(theme_blue, theme_green, theme_red)) +
    labs(
        x = "Key layer", 
		y = "Inverse signing rate)",
		fill = ""
    ) + theme(legend.position = c(0.9, 0.25)) + 
    coord_flip() +
    scale_x_reverse(breaks = unique(data$layer))


line_chart <- ggplot() +
	scale_linetype_manual(values = c("solid", "dashed")) +
	labs(
		x = "Missed messages",
		y = "Messages to re-authenticate",
		color = "",
		linetype = ""
	) +
	
	coord_cartesian(xlim = c(0, max_x), ylim = c(0, max_y), expand = FALSE) +
	scale_linetype_manual(values = c("Mean" = "solid", "Median" = "solid", "Approx" = "dashed", "Quartile" = "dotted")) +
	theme_cowplot(font_size = fsize) +
	theme(legend.position = c(0.02, 0.75), plot.margin = margin(10, 12, 0, 0, "pt"))

for (input_file in files_list) {
	print(paste("Processing file:", input_file))
	file_name <- basename(input_file)

	data2 <- read.table(input_file, header = TRUE, sep = "\t")
	grouped_data2 <- data2 %>%
		summarize(
			num_missed = num_missed,
			mean = mean_reauth,
			probs = 1 / mean_reauth,
			median = ceiling(log(0.5) / log(1 - probs)),
			q25 = ceiling(log(0.25) / log(1 - probs)),
			q75 = ceiling(log(0.75) / log(1 - probs)),
			.groups = "drop"
		)

	grouped_data2$configuration <- data2$configuration

	line_chart <- line_chart +
		geom_step(data = grouped_data2, aes(x = num_missed, y = median, color = configuration), direction = "vh", linewidth = 0.6)
		# geom_step(data = grouped_data2, aes(x = num_missed, y = q75, color = "Approx. quartile"),direction = "vh", linewidth = 0.4) +
		# geom_step(data = grouped_data2, aes(x = num_missed, y = q25, color = "Approx. quartile"),direction = "vh", linewidth = 0.4)
}

ggsave(paste(out_dir, "/", "irates", ".pdf", sep = ""), units = "in", width = full_w, height = 2, chart)
ggsave(paste(out_dir, "/", "base-reauth-interval", ".pdf", sep = ""), units = "in", width = full_w, height = 2, line_chart)
