task default: %i[rubocop validate]

# Rubocop
begin
  require 'rubocop/rake_task'
  RuboCop::RakeTask.new(:rubocop)
rescue LoadError
  puts 'rubocop is not available. Install the rubocop gem to run the lint tests.'
end

# Inspec validation
task :validate do
  sh 'inspec check .'
end
