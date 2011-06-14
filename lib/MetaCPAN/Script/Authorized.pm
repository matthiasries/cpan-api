package MetaCPAN::Script::Authorized;

use Moose;
with 'MooseX::Getopt';
use Log::Contextual qw( :log :dlog );
with 'MetaCPAN::Role::Common';
use List::MoreUtils qw(uniq);

has dry_run => ( is => 'ro', isa => 'Bool', default => 0 );

sub run {
    my $self = shift;
    my $es   = $self->es;
    $self->index->refresh;

    log_info { "Dry run: updates will not be written to ES" }
    if ( $self->dry_run );
    my ( %modules, %authors, @unauthorized );
    my $scroll = $self->scroll;
    log_info { $scroll->total . " files found" };
    while ( my $file = $scroll->next ) {
        my $data = $file->{fields};
        next if ( $data->{distribution} eq 'perl' );
        my @modules = map { $_->{name} } @{ $data->{'_source.module'} };
        foreach my $module (@modules) {
            if (   $modules{$module}
                && $modules{$module} ne $data->{distribution}
                && !grep { $_ eq $data->{author} }
                @{ $authors{$module} || [] } )
            {
                log_info {
"found unauthorized module $module in $data->{distribution}";
                };
                push( @unauthorized,
                    { file => $file->{_id}, module => $module } );
                if ( @unauthorized == 100 ) {
                    $self->bulk_update(@unauthorized);
                    @unauthorized = ();
                }
            }
            else {
                $modules{$module} = $data->{distribution};
                $authors{$module} =
                  [ uniq @{ $authors{$module} || [] }, $data->{author} ];
            }
        }
    }
    $self->bulk_update(@unauthorized) if (@unauthorized);    # update the rest
}

sub bulk_update {
    my ( $self, @unauthorized ) = @_;
    if ( $self->dry_run ) {
        log_info { "dry run, not updating" };
        return;
    }
    my @bulk;
    my $es      = $self->model->es;
    my $results = $es->search(
        index => $self->index->name,
        type  => 'file',
        size  => scalar @unauthorized,
        query => {
            filtered => {
                query  => { match_all => {} },
                filter => {
                    or => [
                        map { { term => { 'file.id' => $_->{file} } } }
                          @unauthorized
                    ]
                }
            }
        }
    );
    my %files =
      map { $_->{_source}->{id} => $_->{_source} }
      @{ $results->{hits}->{hits} };
    foreach my $item (@unauthorized) {
        my $file = $files{ $item->{file} };
        $file->{authorized} = \0
          if ( $file->{documentation}
            && $file->{documentation} eq $item->{module} );
        map { $_->{authorized} = \0 }
          grep { $_->{name} eq $item->{module} } @{ $file->{module} };
        push(
            @bulk,
            {
                create => {
                    index => $self->index->name,
                    type  => 'file',
                    data  => {$file}
                }
            }
        );
    }
    ## bulk here
}

sub scroll {
    my $self = shift;
    return $self->model->es->scrolled_search(
        {
            index => $self->index->name,
            type  => 'file',
            query => {
                filtered => {
                    query  => { match_all => {} },
                    filter => {
                        and => [
                            {
                                not => {
                                    filter => {
                                        term =>
                                          { 'file.module.authorized' => \0 }
                                    }
                                }
                            },
                            { exists => { field => 'file.module.name' } }
                        ]
                    }
                }
            },
            scroll => '1h',
            size   => 1000,
            fields => [qw(distribution _source.module author)],
            sort   => ['date'],
        }
    );
}

1;

__END__

=head1 NAME

MetaCPAN::Script::Authorized - set the C<authorized> property on files

=head1 DESCRIPTION

Unauthorized modules are modules that have been uploaded by by different
user than the previous version of the module unless the name of the
distribution matches.