
library(ggplot2)
library(cowplot)
library(reshape2)

# Read in the data from the file
data <- read.table("reauth_time.tsv", header = TRUE, sep = "\t")

# Compute the mean of num_to_reauth for each combination of the first four columns
data_mean <- aggregate(num_to_reauth ~ key_selection + key_lifetime + PC + num_received + num_missed, data, function(x) c(mean = mean(x), q1 = quantile(x, 0.25), q3 = quantile(x, 0.75)))


# Calculate the median
grouped_data <- data %>%
  group_by(key_selection, key_lifetime, PC, num_received, num_missed) %>%
  summarize(median = median(num_to_reauth),
            q25 = quantile(num_to_reauth, 0.25),
            q75 = quantile(num_to_reauth, 0.75))

line_chart <- ggplot(grouped_data, aes(x = num_missed)) +
  geom_line(aes(y = median, color = "Median"), size = 2) +
  geom_line(aes(y = q75, color = "3rd Quartile"), size = 1) +
  geom_line(aes(y = q25, color = "1st Quartile"), size = 1) +
  scale_color_manual(values = c("Median" = "black", "1st Quartile" = "gray", "3rd Quartile" = "gray")) +
  labs(title = "Median and Upper Quartile of Received Packets",
       x = "Number of Missed Packets",
       y = "Values",
       color = "Statistic") +
  theme_minimal()

# Print the plot
plot


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

