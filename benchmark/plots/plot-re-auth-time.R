
library(ggplot2)
library(cowplot)
library(reshape2)
library(dplyr)
library(stringr)
library(gtable) # Add gtable library
library(grid)   # Add grid library


max_y <- 200

# Get a list of file names in the directory
#file_list <- list.files("data/", pattern = "\\.tsv$", full.names = TRUE)
file_list <- list(
	"data/reauth_time/reauth_time__ksskip-exponential__pc1__kl1.tsv", 
	"data/reauth_time/reauth_time__ksskip-exponential__pc2__kl1.tsv",
	"data/reauth_time/reauth_time__ksskip-exponential__pc10__kl1.tsv"
	)


# Create an empty plot
line_chart <- ggplot() + theme_cowplot(font_size=16) +
	scale_linetype_manual(values = c("solid", "dashed")) +
  labs(	x = "Missed messages",
		y = "Messages to re-authenticate",
		color = "Pre-cert",
		linetype = ""
	) +
	scale_x_continuous(expand = c(0, 0)) +  # Reduce space between x-axis and zero
  	scale_y_continuous(expand = c(0, 0), limits =c(0, max_y)) +  # Reduce space between y-axis and zero
  theme(legend.position = c(0.05, 0.97), plot.margin = margin(10, 12, 0, 0, "pt")) 


for (input_file in file_list) {
	print(paste("Processing file:", input_file));
	file_name <- basename(input_file)
	pc_num <- str_extract(file_name, "(?<=pc)\\d+")
	print(pc_num)

	data <- read.table(input_file, header = TRUE, sep = "\t")
	grouped_data <- data %>% group_by(key_selection, key_lifetime, PC, num_received, num_missed) %>% summarize(median = median(num_to_reauth), q25 = quantile(num_to_reauth, 0.25), q75 = quantile(num_to_reauth, 0.75), .groups = "drop")
	# Add a new column 'pc_num' to the grouped_data data frame
    grouped_data$pc_num <- pc_num

	line_chart <- line_chart +
	    geom_line(data = grouped_data, aes(x = num_missed, y = median, color = factor(pc_num), linetype = "Median"), linewidth = 1) +
		geom_line(data = grouped_data, aes(x = num_missed, y = q75, color = factor(pc_num), linetype = "Quartile"), linewidth = 0.5) +
		geom_line(data = grouped_data, aes(x = num_missed, y = q25, color = factor(pc_num), linetype = "Quartile"), linewidth = 0.5)
}

gt <- ggplotGrob(line_chart)
gt$layout$clip[gt$layout$name == "axis-l"] <- "off"
gt$grobs[[which(gt$layout$name == "axis-l")]]$children[[2]]$hjust <- -0.5


ggsave(paste("out/re-auth-time", ".pdf", sep=""), units='in', width=5, height=4, gt)


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

