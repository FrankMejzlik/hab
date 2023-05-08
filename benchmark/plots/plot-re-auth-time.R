# Include the
library(funr)
main_script_dir <- get_script_path()
included_script_path <- file.path(main_script_dir, "common.R")
source(included_script_path)


max_y <- 1500
max_x <- 1500
max_y <- NA
max_x <- NA


max_xs <- list(1000, NA)

for (max_x in max_xs) {
	print(max_x)

	if (max_x ==1000) {
		max_y <- 500
	}
	files_list <- list(
		list(paste(data_dir, "/reauth/reauth__exp__1__1.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__exp__1__1.tsv", sep="")),
		list(paste(data_dir, "/reauth/reauth__lin__1__1.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__lin__1__1.tsv", sep="")),
		list(paste(data_dir, "/reauth/reauth__log__1__1.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__log__1__1.tsv", sep="")),
		list(paste(data_dir, "/reauth/reauth__exp__20__8.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__exp__20__8.tsv", sep="")),
		list(paste(data_dir, "/reauth/reauth__lin__20__8.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__lin__20__8.tsv", sep="")),
		list(paste(data_dir, "/reauth/reauth__log__20__8.tsv", sep=""), paste(data_dir, "/reauth_approx/reauth__log__20__8.tsv", sep=""))
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
			theme(legend.position = c(0.02, 0.75), plot.margin = margin(10, 12, 0, 0, "pt"))


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
			

			if (max_x ==1000) {
				line_chart <- line_chart + scale_y_continuous(
					name = "Messages to re-authenticate",
				)+ geom_line(data = grouped_data, aes(x = num_missed, y = median, color = "Median"), linewidth = 0.6) +
				geom_line(data = grouped_data, aes(x = num_missed, y = q75, color = "Quartile"), linewidth = 0.4) +
				geom_line(data = grouped_data, aes(x = num_missed, y = q25, color = "Quartile"), linewidth = 0.4) +
				scale_color_manual(values = c("Approx. quartile" = theme_red_light, "Approx. median" = theme_red, "Median" = theme_green, "Quartile" = theme_green_light, "Prob. to re-authenticate" = "black"))
			} else {
				line_chart <- line_chart + scale_y_continuous(
					name = "Messages to re-authenticate",
					limits = c(0, max(grouped_data$mean)),
					sec.axis = sec_axis(~ . / max(grouped_data$mean), name = "Prob. of re-authentication")
				) + geom_line(data = grouped_data, aes(x = num_missed, y = median, color = "Median"), linewidth = 0.6) +
				geom_line(data = grouped_data, aes(x = num_missed, y = q75, color = "Quartile"), linewidth = 0.4) +
				geom_line(data = grouped_data, aes(x = num_missed, y = q25, color = "Quartile"), linewidth = 0.4) +
				geom_line(data = grouped_data, aes(x = num_missed, y = convert_y2_to_y1(miss_prob), color = "Prob. to re-authenticate"), linewidth = 0.5) +
				scale_color_manual(values = c("Approx. quartile" = theme_red_light, "Approx. median" = theme_red, "Median" = theme_green, "Quartile" = theme_green_light, "Prob. to re-authenticate" = "black"))
			}
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
					mean = num_to_reauth,
					probs = 1 / num_to_reauth,
					median = ceiling(log(0.5) / log(1 - probs)),
					q25 = ceiling(log(0.25) / log(1 - probs)),
					q75 = ceiling(log(0.75) / log(1 - probs)),
					.groups = "drop"
				)

			line_chart <- line_chart +
				geom_step(data = grouped_data2, aes(x = num_missed, y = median, color = "Approx. median"), direction = "vh", linewidth = 0.6) +
				geom_step(data = grouped_data2, aes(x = num_missed, y = q75, color = "Approx. quartile"),direction = "vh", linewidth = 0.4) +
				geom_step(data = grouped_data2, aes(x = num_missed, y = q25, color = "Approx. quartile"),direction = "vh", linewidth = 0.4)
		}

		gt <- ggplotGrob(line_chart)
		gt$layout$clip[gt$layout$name == "axis-l"] <- "off"
		gt$grobs[[which(gt$layout$name == "axis-l")]]$children[[2]]$hjust <- 0.5


		ggsave(paste(out_dir, "/re-auth-", max_x, "-", i, ".pdf", sep = ""), units = "in", width = 5.5, height = 2, gt)
	}
}
