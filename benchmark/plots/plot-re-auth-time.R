library(ggplot2)
library(cowplot)
library(reshape2)
library(dplyr)
library(stringr)
library(gtable) # Add gtable library
library(grid) # Add grid library


max_y <- 1500
max_x <- 1500
max_y <- NA
max_x <- NA
fsize <- 10

# Get a list of file names in the directory
# file_list <- list.files("data/", pattern = "\\.tsv$", full.names = TRUE)
file_list <- list(
    "plots/data/reauth/reauth__exp__1__1.tsv"
    # "plots/data/reauth/reauth__exp__1__2.tsv",
    # "plots/data/reauth/reauth__exp__1__3.tsv"
)

file_list_approx <- list(
    "plots/data/reauth_approx/reauth__exp__1__1.tsv"
    # "plots/data/reauth_approx/reauth__exp__1__2.tsv",
    # "plots/data/reauth_approx/reauth__exp__1__3.tsv"
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


miss_chart <- ggplot() +
    scale_linetype_manual(values = c("solid", "dashed")) +
    labs(
        x = "Missed messages",
        y = "Prob. to not re-auth",
    ) +
    coord_cartesian(xlim = c(0, max_x), ylim = c(0, max_y), expand = FALSE) +
    theme_cowplot(font_size = fsize) 


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


ggsave(paste("plots/out/re-auth-time", ".pdf", sep = ""), units = "in", width = 5.5, height = 3, gt)
ggsave(paste("plots/out/re-auth-time-miss", ".pdf", sep = ""), units = "in", width = 5.5, height = 3, miss_chart)


# library(ggplot2)
# library(cowplot)

# x <- read.table('envelope-times.tsv')
# colnames(x) <- c('meas', 'tag', 'seed', 'size', 'nodes', 'breaks', 'dims', 'time')
# tmp <- x[x$meas=='envelope_time.py',]
# x[x$meas=='envelope_time.py', c('seed', 'size', 'nodes', 'breaks')] <- tmp[,c('breaks', 'seed', 'size', 'nodes')]

# source('model-sizes.R')
# x$rxns <- rxns[paste(x$size, x$seed)]

# x$meas=factor(x$meas, levels=c('envelope_time','envelope_time.py'), labels=c('COBREXA.jl', 'COBRApy'))

# bak <- x

# brbreaks <- sort(unique(x$breaks))
# x$fbreaks <- factor(x$breaks, levels=brbreaks, labels=paste0(brbreaks, "³ samples"))

# sizebreaks <- sort(unique(x$size))
# x$size <- factor(x$size, levels=sizebreaks, labels=paste0(sizebreaks, " organisms"))


# if(F) { #original
# ggsave("envelopes.pdf", units='in', width=5.5, height=5,
# ggplot(x, aes(rxns, time, color=meas)) +
#   geom_point(size=1) +
#   stat_quantile(quantiles=c(0.5), size=.5) +
#   theme_cowplot(font_size=9) +
#   scale_x_log10("Model size (reaction count, log-scale)", labels=function(x){print(x);sitools::f2si(x)}) +
#   scale_y_log10("Envelope computation time (seconds, log-scale)") +
#   scale_color_brewer("Software", palette='Set2') +
#   ggtitle("Production envelope computation performance") +
#   facet_grid(breaks~nodes) +
#   theme(
#     panel.grid.major=element_line(size=.2, color='#cccccc'),
#   )
# )
# }

# ggsave("envelopes.pdf", units='in', width=5, height=4,
# ggplot(x, aes(nodes, breaks^3/time, color=meas, group=meas)) +
#   geom_point(size=1, position=position_jitter(width=0.02)) +
#   stat_summary(fun='mean', geom='line') +
#   theme_cowplot(font_size=9) +
#   scale_x_log10("Available resources (CPU count, logarithmic axis)") +
#   scale_y_log10("Computation speed (samples solved per seconds, log-scale)") +
#   scale_color_brewer("Software", palette='Set2') +
#   ggtitle("Production envelope computation performance") +
#   facet_grid(size~fbreaks, scales='free') +
#   theme(
#     panel.grid.major=element_line(size=.2, color='#cccccc'),
#   )
# )

# x <- bak
# x$tps <- x$breaks^3/x$time
# xx <- reshape2::acast(x, nodes~meas~breaks~size, value.var='time', fun.aggregate=mean)
# xx[is.nan(xx)] <- NA
# xx <- reshape2::melt(xx, value.name='time', na.rm=T)
# colnames(xx) <- c('nodes','meas','breaks','size','time')
# xx <- round(reshape2::acast(xx, size+meas+nodes~breaks, value.var='time', fun.aggregate=mean), digits=2)
# write.table(xx, "tab-envelopes.tex", sep=" & ", eol=" \\\\\n", quote=F)
