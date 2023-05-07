# Include the
library(funr)
main_script_dir <- get_script_path()
included_script_path <- file.path(main_script_dir, "common.R")
source(included_script_path)


max_y <- 1500
max_x <- 1500
max_y <- NA
max_x <- NA


files_list <- list(
    list(paste(data_dir, "/reauth/reauth__exp__1__1.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__exp__1__1.tsv", sep="")),
    list(paste(data_dir, "/reauth/reauth__lin__1__1.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__lin__1__1.tsv", sep="")),
    list(paste(data_dir, "/reauth/reauth__log__1__1.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__log__1__1.tsv", sep=""))
)

for (i in seq_along(files_list)) {
	pair <- files_list[[i]]

	file_list <- list(
		pair[[1]]
	)

	file_list_approx <- list(
		pair[[2]]
	)


	# Create an empty plot
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
		theme(legend.position = c(0.05, 0.8), plot.margin = margin(10, 12, 0, 0, "pt"))


	for (input_file in file_list) {
		print(paste("Processing file:", input_file))
		file_name <- basename(input_file)
		pc_num <- str_extract(file_name, "\\d+(?=\\.)")
		key_charges <- str_match(file_name, "(\\d+).*?(\\d+)")
		key_charges <- key_charges[, 2]


		data <- read.table(input_file, header = TRUE, sep = "\t")
		grouped_data <- data %>%
			group_by(key_strategy, key_charges, PC, num_received, num_missed) %>%
			summarize(
				median = median(num_to_reauth, na.rm = TRUE),
				mean = mean(num_to_reauth, na.rm = TRUE),
				q25 = quantile(num_to_reauth, 0.25, na.rm = TRUE),
				q75 = quantile(num_to_reauth, 0.75, na.rm = TRUE),
				miss_prob = 1 - sum(is.na(num_to_reauth)) / n(),
				.groups = "drop"
			)

		convert_y2_to_y1 <- function(y2) {
			max_y1 <- max(grouped_data$mean, na.rm = TRUE)
			print(max_y1)
			y2 * max_y1
		}
		
		line_chart <- line_chart + scale_y_continuous(
			name = "Messages to re-authenticate",
			sec.axis = sec_axis(~ . / max(grouped_data$mean), name = "Prob. of re-authentication")
		) +
			geom_line(data = grouped_data, aes(x = num_missed, y = median, color = "Median"), linewidth = 0.6) +
			#geom_line(data = grouped_data, aes(x = num_missed, y = q75, color = "Quartile"), linewidth = 0.3) +
			#geom_line(data = grouped_data, aes(x = num_missed, y = q25, color = "Quartile"), linewidth = 0.3) +
			geom_line(data = grouped_data, aes(x = num_missed, y = convert_y2_to_y1(miss_prob)), linewidth = 1)
	}

	for (input_file in file_list_approx) {
		print(paste("Processing file:", input_file))
		file_name <- basename(input_file)
		pc_num <- str_extract(file_name, "\\d+(?=\\.)")
		key_charges <- str_match(file_name, "(\\d+).*?(\\d+)")
		key_charges <- key_charges[, 2]

		data2 <- read.table(input_file, header = TRUE, sep = "\t")
		grouped_data2 <- data2 %>%
			group_by(key_strategy, key_charges, PC, num_received, num_missed) %>%
			summarize(
				median = median(num_to_reauth, na.rm = TRUE),
				mean = mean(num_to_reauth, na.rm = TRUE),
				q25 = quantile(num_to_reauth, 0.25, na.rm = TRUE),
				q75 = quantile(num_to_reauth, 0.75, na.rm = TRUE),
				.groups = "drop"
			)

		line_chart <- line_chart +
			geom_step(data = grouped_data2, aes(x = num_missed, y = mean, color = "Approximation"), direction = "vh", linewidth = 1)
	}

	gt <- ggplotGrob(line_chart)
	gt$layout$clip[gt$layout$name == "axis-l"] <- "off"
	gt$grobs[[which(gt$layout$name == "axis-l")]]$children[[2]]$hjust <- 0.5


	ggsave(paste(out_dir, "/re-auth-time-", i, ".pdf", sep = ""), units = "in", width = 5.5, height = 3, gt)
}
